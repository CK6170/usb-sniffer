//go:build windows

package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

//go:embed static/index.html
var indexHTML []byte

//go:embed static/shekel.jpg
var shekelLogo []byte

//go:embed static/favicon.png
var faviconPNG []byte

// ─── SSE broadcaster ──────────────────────────────────────────────────────

type broker struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

func newBroker() *broker { return &broker{clients: make(map[chan string]struct{})} }

func (b *broker) subscribe() chan string {
	ch := make(chan string, 128)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *broker) unsubscribe(ch chan string) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
}

func (b *broker) send(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.clients {
		select {
		case ch <- msg:
		default: // drop if client is slow
		}
	}
}

// ─── WebServer ────────────────────────────────────────────────────────────

type WebServer struct {
	mu      sync.Mutex
	sniffer *Sniffer
	running bool
	port    string
	hub     *broker
}

func newWebServer() *WebServer {
	return &WebServer{hub: newBroker()}
}

// ─── JSON message types ───────────────────────────────────────────────────

type pktMsg struct {
	Type string `json:"type"`
	T    string `json:"t"`
	Dir  string `json:"dir"`
	Src  string `json:"src"`
	PID  uint32 `json:"pid"`
	N    int    `json:"n"`
	B64  string `json:"b64"`
}

type statusMsg struct {
	Type    string `json:"type"`
	Running bool   `json:"running"`
	Port    string `json:"port"`
	Msg     string `json:"msg"`
}

func (ws *WebServer) broadcastStatus(running bool, port, msg string) {
	sm := statusMsg{Type: "status", Running: running, Port: port, Msg: msg}
	b, _ := json.Marshal(sm)
	ws.hub.send("data: " + string(b) + "\n\n")
}

// ─── Handlers ─────────────────────────────────────────────────────────────

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func (ws *WebServer) handlePorts(w http.ResponseWriter, r *http.Request) {
	ports, _ := EnumerateCOMPorts()

	type portEntry struct {
		Port string `json:"port"`
		Name string `json:"name"`
		USB  bool   `json:"usb"`
	}
	var result []portEntry
	for _, p := range ports {
		result = append(result, portEntry{
			Port: p.Port,
			Name: p.FriendlyName,
			USB:  isUSBDevice(p.HardwareID),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (ws *WebServer) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Port string `json:"port"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	ws.mu.Lock()
	already := ws.running
	ws.mu.Unlock()

	if already {
		http.Error(w, "already running", http.StatusConflict)
		return
	}

	cfg := Config{
		Port:   req.Port,
		Silent: true,
		OnPacket: func(pkt Packet) {
			dir := "out"
			if pkt.Dir == DirIn {
				dir = "in"
			}
			pm := pktMsg{
				Type: "packet",
				T:    pkt.Time.Format("15:04:05.000"),
				Dir:  dir,
				Src:  pkt.Source,
				PID:  pkt.ProcessID,
				N:    len(pkt.Data),
				B64:  base64.StdEncoding.EncodeToString(pkt.Data),
			}
			b, _ := json.Marshal(pm)
			ws.hub.send("data: " + string(b) + "\n\n")
		},
	}

	sniffer, err := NewSniffer(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ws.mu.Lock()
	ws.sniffer = sniffer
	ws.running = true
	ws.port = req.Port
	ws.mu.Unlock()

	go func() {
		ws.broadcastStatus(true, req.Port, "")
		runErr := sniffer.Run()
		// Only update state if this goroutine's sniffer is still current
		// (handleStop may have already cleared it; a new capture may be running).
		ws.mu.Lock()
		isCurrent := ws.sniffer == sniffer
		if isCurrent {
			ws.running = false
			ws.sniffer = nil
		}
		ws.mu.Unlock()
		if isCurrent {
			errMsg := ""
			if runErr != nil {
				errMsg = runErr.Error()
			}
			ws.broadcastStatus(false, "", errMsg)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (ws *WebServer) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Optimistically clear running state so Start is immediately re-enabled,
	// even before Run() returns (it blocks until the subprocess exits).
	ws.mu.Lock()
	s := ws.sniffer
	ws.sniffer = nil
	ws.running = false
	ws.mu.Unlock()

	if s != nil {
		s.Close()
	}
	ws.broadcastStatus(false, "", "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (ws *WebServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send current state immediately.
	ws.mu.Lock()
	cur := statusMsg{Type: "status", Running: ws.running, Port: ws.port}
	ws.mu.Unlock()
	if b, err := json.Marshal(cur); err == nil {
		fmt.Fprintf(w, "data: %s\n\n", b)
		fl.Flush()
	}

	ch := ws.hub.subscribe()
	defer ws.hub.unsubscribe(ch)

	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprint(w, msg)
			fl.Flush()
		case <-tick.C:
			fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

// ─── Entry point ─────────────────────────────────────────────────────────

func RunWebUI() error {
	if !isAdmin() {
		fmt.Fprintln(os.Stderr, "Administrator privileges required. Right-click → Run as administrator.")
		os.Exit(1)
	}

	ws := newWebServer()

	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/shekel.jpg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(shekelLogo)
	})
	mux.HandleFunc("/favicon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(faviconPNG)
	})
	mux.HandleFunc("/api/ports", ws.handlePorts)
	mux.HandleFunc("/api/start", ws.handleStart)
	mux.HandleFunc("/api/stop", ws.handleStop)
	mux.HandleFunc("/events", ws.handleEvents)

	ln, err := net.Listen("tcp", "127.0.0.1:7891")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	go http.Serve(ln, mux)

	url := "http://127.0.0.1:7891"
	fmt.Printf("\n  USB Sniffer  →  %s\n\n", url)
	fmt.Println("  Press Ctrl+C to quit.")
	fmt.Println()

	openBrowser(url)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	// Stop any active capture gracefully.
	ws.mu.Lock()
	s := ws.sniffer
	ws.mu.Unlock()
	if s != nil {
		s.Close()
	}

	fmt.Println("\n[stopped]")
	return nil
}

func openBrowser(url string) {
	exec.Command("cmd", "/c", "start", url).Start()
}

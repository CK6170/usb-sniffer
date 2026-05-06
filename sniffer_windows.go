package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── ETW provider GUIDs ───────────────────────────────────────────────────────

var (
	guidUsbUcx = windows.GUID{
		Data1: 0xA50E8E4A, Data2: 0xB834, Data3: 0x4BFC,
		Data4: [8]byte{0x9E, 0x74, 0x0F, 0x7B, 0x0B, 0x62, 0xB0, 0xC9},
	}
	guidUsbHub3 = windows.GUID{
		Data1: 0x7426A56B, Data2: 0xE2D5, Data3: 0x4B30,
		Data4: [8]byte{0xBD, 0xEF, 0xB3, 0x18, 0x15, 0xC1, 0xA7, 0x4A},
	}
	guidKernelFile = windows.GUID{
		Data1: 0xEDD08927, Data2: 0x9CC4, Data3: 0x4E65,
		Data4: [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89},
	}
)

// ─── Direction ────────────────────────────────────────────────────────────────

type Direction uint8

const (
	DirOut Direction = iota
	DirIn
)

func (d Direction) String() string {
	if d == DirIn {
		return "DEV→HOST"
	}
	return "HOST→DEV"
}

// ─── Packet ───────────────────────────────────────────────────────────────────

type Packet struct {
	Time      time.Time
	Dir       Direction
	Data      []byte
	ProcessID uint32
	Source    string
}

// ─── Config ───────────────────────────────────────────────────────────────────

type Config struct {
	Port     string
	Verbose  bool
	Color    bool
	Silent   bool           // suppress all console output
	OnPacket func(Packet)   // if set, called instead of printing to terminal
}

// ─── Package-level ETW callback ───────────────────────────────────────────────
// Must be a package-level function (not a closure) for syscall.NewCallback.

var gSniffer *Sniffer
var gCB = syscall.NewCallback(etwCallbackThunk)

func etwCallbackThunk(recordPtr uintptr) uintptr {
	s := gSniffer
	if s == nil || recordPtr == 0 {
		return 0
	}
	// Convert uintptr → *EVENT_RECORD via a pointer-to-pointer cast to avoid the
	// "uintptr → unsafe.Pointer" vet rule. The pointer is valid for the duration
	// of this callback (ETW guarantees the record buffer lifetime).
	type ptrHolder struct{ p uintptr }
	ph := ptrHolder{p: recordPtr}
	rec := *(**EVENT_RECORD)(unsafe.Pointer(&ph))
	s.handleETWRecord(rec)
	return 0
}

// ─── Sniffer ──────────────────────────────────────────────────────────────────

type Sniffer struct {
	cfg     Config
	session *etwSession
	display *Display
	closed  atomic.Int32
	pktCh   chan Packet
}

func NewSniffer(cfg Config) (*Sniffer, error) {
	s := &Sniffer{
		cfg:     cfg,
		display: NewDisplay(cfg.Color),
		pktCh:   make(chan Packet, 256),
	}

	if !cfg.Silent {
		// Print detected ports.
		if cfg.Port != "" {
			info, err := FindCOMPort(cfg.Port)
			if err != nil {
				return nil, fmt.Errorf("cannot find %s: %w", cfg.Port, err)
			}
			fmt.Printf("Found: %s  —  %s\n", info.Port, info.FriendlyName)
			fmt.Printf("       HW ID:    %s\n", info.HardwareID)
			fmt.Printf("       Instance: %s\n\n", info.InstanceID)
		} else {
			ports, _ := EnumerateCOMPorts()
			var lines []string
			for _, p := range ports {
				if isUSBDevice(p.HardwareID) {
					lines = append(lines, fmt.Sprintf("  %-6s  %s", p.Port, p.FriendlyName))
				}
			}
			if len(lines) > 0 {
				fmt.Println("USB serial ports detected:")
				fmt.Println(strings.Join(lines, "\n"))
			}
			fmt.Println()
		}
	} else if cfg.Port != "" {
		// Silent mode: still need to validate port exists, but don't print.
		if _, err := FindCOMPort(cfg.Port); err != nil {
			return nil, fmt.Errorf("cannot find %s: %w", cfg.Port, err)
		}
	}

	return s, nil
}

// Run tries USBPcap first; falls back to ETW if USBPcap is not installed.
func (s *Sniffer) Run() error {
	// Display goroutine — reads from pktCh, calls OnPacket callback or prints.
	go func() {
		for pkt := range s.pktCh {
			if s.cfg.OnPacket != nil {
				s.cfg.OnPacket(pkt)
			} else if !s.cfg.Silent {
				s.display.Print(pkt)
			}
		}
	}()

	pcapDevs := FindUSBPcapDevices()

	if len(pcapDevs) > 0 {
		return s.runUSBPcap(pcapDevs)
	}

	if !s.cfg.Silent {
		fmt.Println("[info] USBPcap not found — falling back to ETW (metadata only).")
		fmt.Println("[info] For actual data capture with FTDI devices, install USBPcap:")
		fmt.Println("[info]   https://desowin.org/usbpcap/")
		fmt.Println()
	}
	return s.runETW()
}

// ─── USBPcap path ─────────────────────────────────────────────────────────────

func (s *Sniffer) runUSBPcap(devs []string) error {
	isFTDI := false
	var targetDevice uint16

	if s.cfg.Port != "" {
		info, err := FindCOMPort(s.cfg.Port)
		if err == nil {
			isFTDI = strings.Contains(strings.ToUpper(info.HardwareID), "FTDIBUS")

			// Narrow to the hub serving this port.
			if hub := FindUSBPcapForPort(s.cfg.Port, devs); hub != "" {
				if !s.cfg.Silent {
					fmt.Printf("[info] %s mapped to hub %s\n", s.cfg.Port, hub)
				}
				devs = []string{hub}
			} else if !s.cfg.Silent {
				fmt.Println("[warn] hub detection failed — capturing all USBPcap devices")
			}

			// Get the real USB device address for per-device filtering.
			if addr, err := FindUSBDeviceNumber(info.InstanceID); err == nil {
				targetDevice = addr
				if !s.cfg.Silent {
					fmt.Printf("[info] USB device address: %d\n", targetDevice)
				}
			} else if !s.cfg.Silent {
				fmt.Printf("[warn] USB device address lookup: %v\n", err)
			}
		}
	}
	if isFTDI && !s.cfg.Silent {
		fmt.Println("[info] FTDI device — stripping 2-byte modem-status prefix from IN packets.")
	}

	// Strategy 1: spawn USBPcapCMD.exe (matches whatever driver version is installed).
	if cmdExe := FindUSBPcapCMD(); cmdExe != "" {
		if !s.cfg.Silent {
			fmt.Printf("[info] Using %s\n", cmdExe)
			fmt.Println()
		}
		var started int
		errCh := make(chan error, len(devs))
		for _, dev := range devs {
			dev := dev
			started++
			go func() {
				errCh <- RunUSBPcapCMD(cmdExe, dev, isFTDI, targetDevice, s.cfg.Verbose, s.pktCh)
			}()
		}
		for i := 0; i < started; i++ {
			if err := <-errCh; err != nil && s.closed.Load() == 0 {
				fmt.Printf("[warn] %v\n", err)
			}
		}
		return nil
	}

	// Strategy 2: direct overlapped API.
	if !s.cfg.Silent {
		fmt.Printf("[info] USBPcapCMD.exe not found — trying direct API on %s\n", strings.Join(devs, ", "))
		fmt.Println()
	}

	var started int
	errCh := make(chan error, len(devs))
	for _, dev := range devs {
		dev := dev
		r, err := OpenUSBPcap(dev, isFTDI)
		if err != nil {
			fmt.Printf("[warn] open %s: %v\n", dev, err)
			continue
		}
		started++
		go func() {
			err := r.ReadPackets(targetDevice, s.cfg.Verbose, s.pktCh)
			r.Close()
			errCh <- err
		}()
	}

	if started == 0 {
		return fmt.Errorf("could not open any USBPcap device")
	}

	for i := 0; i < started; i++ {
		if err := <-errCh; err != nil && s.closed.Load() == 0 {
			fmt.Printf("[warn] reader error: %v\n", err)
		}
	}
	return nil
}

// ─── ETW path ─────────────────────────────────────────────────────────────────

func (s *Sniffer) runETW() error {
	gSniffer = s

	session, err := startSession()
	if err != nil {
		return fmt.Errorf("ETW session: %w", err)
	}
	s.session = session

	for _, guid := range []*windows.GUID{&guidUsbUcx, &guidUsbHub3, &guidKernelFile} {
		if err := session.enableProvider(guid); err != nil && s.cfg.Verbose {
			fmt.Printf("[warn] %v\n", err)
		}
	}

	if err := session.openForConsumption(gCB); err != nil {
		session.close()
		return err
	}

	return session.processTrace()
}

func (s *Sniffer) Close() {
	if s.closed.CompareAndSwap(0, 1) {
		if s.session != nil {
			s.session.close()
		}
		close(s.pktCh)
	}
}

// ─── ETW event handler ────────────────────────────────────────────────────────

func (s *Sniffer) handleETWRecord(r *EVENT_RECORD) {
	id := r.EventHeader.EventDescriptor.Id
	prov := r.EventHeader.ProviderId

	switch prov {
	case guidUsbUcx:
		s.handleUCX(r, id)
	case guidKernelFile:
		if s.cfg.Verbose {
			s.handleKernelFile(r, id)
		}
	default:
		if s.cfg.Verbose && !s.cfg.Silent {
			ts := etwTime(r.EventHeader.TimeStamp)
			fmt.Printf("[%s] ETW id=%-4d PID=%-6d len=%d\n",
				ts.Format("15:04:05.000"), id, r.EventHeader.ProcessId, r.UserDataLength)
		}
	}
}

// UCX transfer events — only fire for Microsoft usbser.sys devices, NOT FTDI.
func (s *Sniffer) handleUCX(r *EVENT_RECORD, id uint16) {
	// Event IDs 310/311/312 are bulk/interrupt transfer send/receive/complete.
	if id != 310 && id != 311 && id != 312 {
		if s.cfg.Verbose {
			fmt.Printf("[%s] UCX event id=%d\n",
				etwTime(r.EventHeader.TimeStamp).Format("15:04:05.000"), id)
		}
		return
	}
	data := etwUserData(r)
	if len(data) < 20 {
		return
	}
	epType := data[16]
	if epType != 2 && epType != 3 { // only bulk(2) and interrupt(3)
		return
	}
	bufLen := int(binary32(data[8:]))
	if bufLen <= 0 || 20+bufLen > len(data) {
		return
	}
	dir := DirOut
	if id == 311 || data[17] != 0 {
		dir = DirIn
	}
	payload := make([]byte, bufLen)
	copy(payload, data[20:])
	s.pktCh <- Packet{
		Time:      etwTime(r.EventHeader.TimeStamp),
		Dir:       dir,
		Data:      payload,
		ProcessID: r.EventHeader.ProcessId,
		Source:    "ETW/UCX",
	}
}

func (s *Sniffer) handleKernelFile(r *EVENT_RECORD, id uint16) {
	if id != 15 && id != 16 {
		return
	}
	data := etwUserData(r)
	if !containsUTF16(data, "Serial") && !containsUTF16(data, "COM") {
		return
	}
	verb := "Read "
	if id == 16 {
		verb = "Write"
	}
	fmt.Printf("[%s] KernelFile %s PID=%-6d (%d bytes)\n",
		etwTime(r.EventHeader.TimeStamp).Format("15:04:05.000"),
		verb, r.EventHeader.ProcessId, r.UserDataLength)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type sliceHeader struct{ Data uintptr; Len, Cap int }

func etwUserData(r *EVENT_RECORD) []byte {
	if r.UserDataLength == 0 || r.UserData == 0 {
		return nil
	}
	n := int(r.UserDataLength)
	sh := sliceHeader{Data: r.UserData, Len: n, Cap: n}
	return *(*[]byte)(unsafe.Pointer(&sh))
}

func etwTime(ft int64) time.Time {
	const epoch = 116444736000000000
	return time.Unix(0, (ft-epoch)*100)
}

func containsUTF16(buf []byte, s string) bool {
	pat := make([]byte, len(s)*2)
	for i, c := range s {
		pat[i*2] = byte(c)
	}
outer:
	for i := 0; i <= len(buf)-len(pat); i++ {
		for j, b := range pat {
			if buf[i+j] != b {
				continue outer
			}
		}
		return true
	}
	return false
}

// binary32 reads a little-endian uint32 from b[0:4].
func binary32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

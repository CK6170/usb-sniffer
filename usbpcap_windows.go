package main

// USBPcap capture — two strategies, tried in order:
//
//  1. Subprocess: spawn USBPcapCMD.exe (installed with USBPcap) and parse its
//     pcap stdout. Most reliable because the official tool handles driver
//     version differences internally.
//
//  2. Direct API: open \\.\USBPcapN with FILE_FLAG_OVERLAPPED, send
//     configuration IOCTLs, and read the pcap stream directly. Fallback when
//     USBPcapCMD.exe is not found.
//
// Install USBPcap: https://desowin.org/usbpcap/

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── IOCTL codes ──────────────────────────────────────────────────────────────

const (
	ioctlSetSnaplen   uint32 = 0xf2a06010 // CTL_CODE(0xf2a0, 0x804, BUFFERED, READ)
	ioctlSetFiltering uint32 = 0xf2a06000 // CTL_CODE(0xf2a0, 0x800, BUFFERED, READ)
)

type usbpcapFilter struct {
	addresses [4]uint32
	filterAll uint8
	_         [3]byte
}

// ─── pcap wire format ─────────────────────────────────────────────────────────

const pcapMagic uint32 = 0xa1b2c3d4

type pcapGlobalHdr struct {
	Magic, VerMaj, VerMin uint32 // VerMaj/VerMin are uint16 but packed as 32-bit read
	_                     [8]byte
	SnapLen, LinkType     uint32
}

type pcapRecHdr struct {
	TsSec, TsUsec, CapLen, OrigLen uint32
}

const usbHdrWireSize = 27

// transferName returns a human-readable USB transfer type.
func transferName(t uint8) string {
	switch t {
	case 0:
		return "iso"
	case 1:
		return "interrupt"
	case 2:
		return "control"
	case 3:
		return "bulk"
	default:
		return fmt.Sprintf("type%d", t)
	}
}

// ─── Common pcap stream parser ────────────────────────────────────────────────

// parsePcapStream reads a USBPcap pcap stream.
// verbose=true prints every USB packet (useful for diagnosing "no data").
func parsePcapStream(ctx context.Context, r io.Reader, isFTDI bool, targetDevice uint16, verbose bool, out chan<- Packet) error {
	ghdr := make([]byte, 24) // pcap global header is 24 bytes
	if _, err := io.ReadFull(r, ghdr); err != nil {
		return fmt.Errorf("pcap global header: %w", err)
	}
	magic := binary.LittleEndian.Uint32(ghdr[0:4])
	if magic != pcapMagic {
		return fmt.Errorf("unexpected pcap magic 0x%08x (want 0x%08x)", magic, pcapMagic)
	}

	if verbose {
		fmt.Println("[verbose] pcap stream open — showing all USB packets")
	} else {
		fmt.Println("[info] capture active — waiting for bulk/interrupt traffic on COM port...")
	}

	rhdrBuf := make([]byte, 16)
	usbBuf := make([]byte, usbHdrWireSize)
	var total, bulk int

	for {
		if _, err := io.ReadFull(r, rhdrBuf); err != nil {
			if isNormalEOF(err) {
				if total == 0 {
					fmt.Println("[warn] capture ended with 0 USB packets — is the device in use?")
				} else {
					fmt.Printf("[info] capture ended: %d USB packets seen, %d bulk/interrupt\n", total, bulk)
				}
				return nil
			}
			return fmt.Errorf("record header: %w", err)
		}
		tsSec := binary.LittleEndian.Uint32(rhdrBuf[0:4])
		tsUsec := binary.LittleEndian.Uint32(rhdrBuf[4:8])
		caplen := int(binary.LittleEndian.Uint32(rhdrBuf[8:12]))
		total++

		if caplen < usbHdrWireSize {
			io.ReadFull(r, make([]byte, caplen)) //nolint:errcheck
			continue
		}

		if _, err := io.ReadFull(r, usbBuf); err != nil {
			if isNormalEOF(err) {
				return nil
			}
			return fmt.Errorf("usb header: %w", err)
		}
		remaining := caplen - usbHdrWireSize

		headerLen := int(binary.LittleEndian.Uint16(usbBuf[0:2]))
		endpoint := usbBuf[21]
		transfer := usbBuf[22]
		dataLength := int(binary.LittleEndian.Uint32(usbBuf[23:27]))
		bus := binary.LittleEndian.Uint16(usbBuf[17:19])
		device := binary.LittleEndian.Uint16(usbBuf[19:21])
		isIN := endpoint&0x80 != 0

		if extra := headerLen - usbHdrWireSize; extra > 0 && extra <= remaining {
			io.ReadFull(r, make([]byte, extra)) //nolint:errcheck
			remaining -= extra
		}

		if dataLength > remaining {
			dataLength = remaining
		}
		payloadBuf := make([]byte, remaining)
		if _, err := io.ReadFull(r, payloadBuf); err != nil {
			if isNormalEOF(err) {
				return nil
			}
			return fmt.Errorf("payload: %w", err)
		}
		payload := payloadBuf[:dataLength]

		if verbose {
			dirStr := "OUT"
			if isIN {
				dirStr = "IN "
			}
			fmt.Printf("[usb] bus=%d dev=%d ep=0x%02x %-9s %s  %d bytes\n",
				bus, device, endpoint, transferName(transfer), dirStr, dataLength)
		}

		// Skip obviously non-serial packets (USB serial is always ≤ 512 bytes).
		if dataLength > 512 {
			continue
		}

		// Only bulk(3) and interrupt(1) carry serial data.
		if transfer != 3 && transfer != 1 {
			continue
		}

		// FTDI FT231X always uses EP 0x81 (bulk IN) and EP 0x02 (bulk OUT).
		// Filter to these endpoints to eliminate noise from other devices on the hub.
		if isFTDI && endpoint != 0x81 && endpoint != 0x02 {
			continue
		}

		// Apply device filter.
		if targetDevice != 0 && device != targetDevice {
			continue
		}
		bulk++

		// FTDI wraps each bulk-IN packet with a 2-byte modem-status header.
		if isFTDI && isIN {
			if len(payload) <= 2 {
				continue // status-only packet, no actual data
			}
			payload = payload[2:]
		}
		if len(payload) == 0 {
			continue
		}

		dir := DirOut
		if isIN {
			dir = DirIn
		}
		pkt := Packet{
			Time:   time.Unix(int64(tsSec), int64(tsUsec)*1000),
			Dir:    dir,
			Data:   payload,
			Source: fmt.Sprintf("USB bus=%d dev=%d ep=0x%02x", bus, device, endpoint),
		}
		select {
		case out <- pkt:
		case <-ctx.Done():
			return nil // sniffer was stopped
		}
	}
}

// ─── Strategy 1: USBPcapCMD.exe subprocess ───────────────────────────────────

// FindUSBPcapCMD searches common installation paths for USBPcapCMD.exe.
func FindUSBPcapCMD() string {
	candidates := []string{
		`C:\Program Files\USBPcap\USBPcapCMD.exe`,
		`C:\Program Files (x86)\USBPcap\USBPcapCMD.exe`,
		`C:\Program Files\Wireshark\extcap\USBPcapCMD.exe`,
		`C:\Program Files (x86)\Wireshark\extcap\USBPcapCMD.exe`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("USBPcapCMD.exe"); err == nil {
		return p
	}
	return ""
}

// RunUSBPcapCMD spawns USBPcapCMD.exe for one device and parses its pcap stdout.
// Blocks until the command exits or an unrecoverable error occurs.
// Cancelling ctx kills the subprocess immediately.
func RunUSBPcapCMD(ctx context.Context, exe, dev string, isFTDI bool, targetDevice uint16, verbose bool, out chan<- Packet) error {
	// -d device  -o - (stdout)  -b snaplen  -A (all devices)
	cmd := exec.CommandContext(ctx, exe, "-d", dev, "-o", "-", "-b", "65535", "-A")
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", exe, err)
	}
	defer cmd.Wait()

	return parsePcapStream(ctx, stdout, isFTDI, targetDevice, verbose, out)
}

// ─── Strategy 2: direct overlapped API ───────────────────────────────────────

// FindUSBPcapDevices returns every \\.\USBPcapN that can be opened.
func FindUSBPcapDevices() []string {
	var out []string
	for i := 1; i <= 9; i++ {
		path := fmt.Sprintf(`\\.\USBPcap%d`, i)
		pathW, _ := windows.UTF16PtrFromString(path)
		h, err := windows.CreateFile(pathW,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil, windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED, 0)
		if err == nil {
			windows.CloseHandle(h)
			out = append(out, path)
		}
	}
	return out
}

type USBPcapReader struct {
	handle  windows.Handle
	ioEvent windows.Handle
	isFTDI  bool
}

func OpenUSBPcap(path string, isFTDI bool) (*USBPcapReader, error) {
	pathW, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(pathW,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}

	r := &USBPcapReader{handle: h, ioEvent: ev, isFTDI: isFTDI}

	// Configure; ignore errors — driver may already auto-start capture.
	snaplen := uint32(65535)
	r.ioctl(ioctlSetSnaplen, unsafe.Pointer(&snaplen), 4)
	flt := usbpcapFilter{filterAll: 1}
	r.ioctl(ioctlSetFiltering, unsafe.Pointer(&flt), uint32(unsafe.Sizeof(flt)))

	return r, nil
}

func (r *USBPcapReader) ioctl(code uint32, in unsafe.Pointer, inLen uint32) error {
	var n uint32
	return windows.DeviceIoControl(r.handle, code,
		(*byte)(in), inLen, nil, 0, &n, nil)
}

func (r *USBPcapReader) sysRead(buf []byte) (int, error) {
	windows.ResetEvent(r.ioEvent)
	ov := windows.Overlapped{HEvent: r.ioEvent}
	var n uint32
	err := windows.ReadFile(r.handle, buf, &n, &ov)
	if err == windows.ERROR_IO_PENDING {
		if _, werr := windows.WaitForSingleObject(r.ioEvent, windows.INFINITE); werr != nil {
			return 0, werr
		}
		err = windows.GetOverlappedResult(r.handle, &ov, &n, false)
	}
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// ReadPackets wraps the overlapped reader as an io.Reader for parsePcapStream.
func (r *USBPcapReader) ReadPackets(ctx context.Context, targetDevice uint16, verbose bool, out chan<- Packet) error {
	return parsePcapStream(ctx, r, r.isFTDI, targetDevice, verbose, out)
}

// Read implements io.Reader using overlapped I/O.
func (r *USBPcapReader) Read(b []byte) (int, error) { return r.sysRead(b) }

func (r *USBPcapReader) Close() {
	windows.CancelIoEx(r.handle, nil)
	windows.CloseHandle(r.handle)
	windows.CloseHandle(r.ioEvent)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isNormalEOF(err error) bool {
	if err == nil || err == io.EOF || err == io.ErrUnexpectedEOF {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "closed") ||
		strings.Contains(msg, "invalid handle") ||
		strings.Contains(msg, "aborted") ||
		strings.Contains(msg, "cancelled")
}

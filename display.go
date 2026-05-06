package main

// Hex-dump display layer. Formats captured packets to stdout.

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	bytesPerRow = 16

	// ANSI colors
	colorReset  = "\x1b[0m"
	colorCyan   = "\x1b[36m"  // host→device
	colorYellow = "\x1b[33m"  // device→host
	colorGray   = "\x1b[90m"  // address / separator
	colorBold   = "\x1b[1m"
)

type Display struct {
	color bool
}

func NewDisplay(color bool) *Display {
	return &Display{color: color}
}

// Print renders a captured packet as a formatted hex dump.
func (d *Display) Print(pkt Packet) {
	if len(pkt.Data) == 0 {
		return
	}

	dirColor := colorCyan
	if pkt.Dir == DirIn {
		dirColor = colorYellow
	}

	header := fmt.Sprintf("[%s]  %s  PID=%-6d  %d bytes  (%s)",
		pkt.Time.Format("15:04:05.000"),
		pkt.Dir,
		pkt.ProcessID,
		len(pkt.Data),
		pkt.Source,
	)

	if d.color {
		fmt.Printf("%s%s%s%s\n%s", colorBold, dirColor, header, colorReset, colorReset)
	} else {
		fmt.Println(header)
	}

	d.hexDump(pkt.Data, dirColor)
	fmt.Println()
}

// PrintVerbose prints a one-line summary for non-data ETW events.
func (d *Display) PrintVerbose(record *EVENT_RECORD) {
	ts := etwTime(record.EventHeader.TimeStamp)
	fmt.Printf("[%s]  ETW  provider=%v  id=%-4d  PID=%d  len=%d\n",
		ts.Format("15:04:05.000"),
		record.EventHeader.ProviderId,
		record.EventHeader.EventDescriptor.Id,
		record.EventHeader.ProcessId,
		record.UserDataLength,
	)
}

// hexDump writes a formatted hex+ASCII dump of b to stdout.
func (d *Display) hexDump(b []byte, lineColor string) {
	for offset := 0; offset < len(b); offset += bytesPerRow {
		end := offset + bytesPerRow
		if end > len(b) {
			end = len(b)
		}
		row := b[offset:end]

		// Address
		if d.color {
			fmt.Printf("%s%08x%s  ", colorGray, offset, colorReset)
		} else {
			fmt.Printf("%08x  ", offset)
		}

		// Hex bytes — two groups of 8
		hex1 := hexGroup(row, 0, 8)
		hex2 := hexGroup(row, 8, 16)
		pad1 := strings.Repeat("   ", 8-min(len(row), 8))
		pad2 := ""
		if len(row) < 16 {
			remaining := 16 - len(row)
			if remaining > 8 {
				pad2 = strings.Repeat("   ", remaining-8)
			}
		}

		if d.color {
			fmt.Printf("%s%s%s%s  %s%s%s  ", lineColor, hex1, colorReset, pad1, lineColor, hex2, colorReset)
		} else {
			fmt.Printf("%-23s  %-23s  ", hex1+pad1, hex2+pad2)
		}

		// ASCII
		fmt.Printf("|%s|\n", asciiRow(row))
	}
}

func hexGroup(b []byte, start, end int) string {
	var sb strings.Builder
	for i := start; i < end && i < len(b); i++ {
		if i > start {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", b[i])
	}
	return sb.String()
}

func asciiRow(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		r := rune(c)
		if c < 128 && unicode.IsPrint(r) {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

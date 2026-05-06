//go:build windows

package main

import (
	"fmt"
	"testing"
)

func TestFindUSBDeviceNumber(t *testing.T) {
	instanceID := `FTDIBUS\VID_0403+PID_6015+D30AFAXUA\0000`

	hcPaths := getAllInterfacePaths(guidUSBHostController)
	fmt.Printf("Found %d host controllers:\n", len(hcPaths))
	for _, hc := range hcPaths {
		rootHub := getRootHubPath(hc)
		fmt.Printf("  HC: %s\n     root hub: %s\n", hc, rootHub)
		if rootHub != "" {
			n := hubPortCount(rootHub)
			fmt.Printf("     port count: %d\n", n)
			for port := uint32(1); port <= n && port <= 16; port++ {
				vid, pid, addr, isHub := probeConnInfo(rootHub, port)
				if vid != 0 {
					fmt.Printf("     port %d: VID_%04X PID_%04X addr=%d hub=%v\n", port, vid, pid, addr, isHub)
				}
			}
		}
	}

	addr, err := FindUSBDeviceNumber(instanceID)
	if err != nil {
		t.Logf("FindUSBDeviceNumber error: %v", err)
	} else {
		t.Logf("USB device address: %d", addr)
	}
}

func TestParseVIDPID(t *testing.T) {
	tests := []struct {
		id  string
		vid uint16
		pid uint16
	}{
		{`USB\VID_0403&PID_6015\D30AFAXU`, 0x0403, 0x6015},
		{`USB\VID_2109&PID_2817\...`, 0x2109, 0x2817},
	}
	for _, tt := range tests {
		vid, pid := parseVIDPID(tt.id)
		if vid != tt.vid || pid != tt.pid {
			t.Errorf("%s: got VID=%04X PID=%04X, want VID=%04X PID=%04X", tt.id, vid, pid, tt.vid, tt.pid)
		}
	}
}

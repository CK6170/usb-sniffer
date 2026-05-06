package main

// Hub detection and USB device address resolution.
//
// IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX must be sent to the hub's FDO
// (usbhub.sys). Opening a hub via CM_Get_Device_Interface_ListW gives a
// handle to the PDO, which silently returns 0 bytes for hub IOCTLs.
//
// Correct approach (same as USBView):
//  1. Enumerate USB host controllers via GUID_DEVINTERFACE_USB_HOST_CONTROLLER.
//  2. Call IOCTL_USB_GET_ROOT_HUB_NAME on each HC to get the root hub's FDO
//     path (a symbolic link in \??\  — prefixed with \\.\  for Win32 use).
//  3. Recursively walk child hubs via IOCTL_USB_GET_NODE_CONNECTION_NAME.
//     These names also resolve directly to the hub FDO.
//  4. Probe each port with IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX to
//     get VID/PID/device-address.

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── cfgmgr32 bindings ───────────────────────────────────────────────────────

var (
	cfgmgr32                          = windows.NewLazySystemDLL("cfgmgr32.dll")
	procCMLocateDevNodeW              = cfgmgr32.NewProc("CM_Locate_DevNodeW")
	procCMGetParent                   = cfgmgr32.NewProc("CM_Get_Parent")
	procCMGetDeviceIDW                = cfgmgr32.NewProc("CM_Get_Device_IDW")
	procCMGetDevNodeRegistryPropW     = cfgmgr32.NewProc("CM_Get_DevNode_Registry_PropertyW")
	procCMGetDeviceInterfaceListSizeW = cfgmgr32.NewProc("CM_Get_Device_Interface_List_SizeW")
	procCMGetDeviceInterfaceListW     = cfgmgr32.NewProc("CM_Get_Device_Interface_ListW")
)

const (
	crSuccess    = 0
	cmDRPAddress = 0x1D
)

// GUID_DEVINTERFACE_USB_HUB {f18a0e88-c30c-11d0-8815-00a0c906bed8}
var guidUSBHub = windows.GUID{
	Data1: 0xf18a0e88, Data2: 0xc30c, Data3: 0x11d0,
	Data4: [8]byte{0x88, 0x15, 0x00, 0xa0, 0xc9, 0x06, 0xbe, 0xd8},
}

// GUID_DEVINTERFACE_USB_HOST_CONTROLLER {3ABF6F2D-71C4-462A-8A92-1E6861E6AF27}
var guidUSBHostController = windows.GUID{
	Data1: 0x3ABF6F2D, Data2: 0x71C4, Data3: 0x462A,
	Data4: [8]byte{0x8A, 0x92, 0x1E, 0x68, 0x61, 0xE6, 0xAF, 0x27},
}

// All USB hub IOCTL codes: CTL_CODE(FILE_DEVICE_USB=0x22, func, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
// Function numbers from WDK usbioctl.h (HCD_* for host controller, USB_* for hub):
//   HCD_GET_ROOT_HUB_NAME               = 258 (0x102) → 0x00220408
//   USB_GET_NODE_INFORMATION             = 258 (0x102) → 0x00220408  (same code, different device)
//   USB_GET_NODE_CONNECTION_NAME         = 260 (0x104) → 0x00220410
//   USB_GET_NODE_CONNECTION_INFORMATION_EX = 276 (0x114) → 0x00220450
const (
	// Sent to HC  → returns USB_ROOT_HUB_NAME.
	// Sent to hub → returns USB_NODE_INFORMATION (port count etc).
	ioctlUSBGetNodeInfo uint32 = 0x00220408

	// Alias for clarity when used on a host controller.
	ioctlUSBGetRootHubName uint32 = 0x00220408

	// Sent to hub → returns USB_NODE_CONNECTION_INFORMATION_EX (VID/PID/address).
	ioctlUSBGetNodeConnInfoEx uint32 = 0x00220450

	// Sent to hub → returns USB_NODE_CONNECTION_INFORMATION (non-EX, function 259).
	// Same struct layout through DeviceAddress; fallback if EX variant fails.
	ioctlUSBGetNodeConnInfo uint32 = 0x0022040C
)

// ─── cfgmgr32 helpers ────────────────────────────────────────────────────────

func cmLocateDevNode(instanceID string) (uint32, error) {
	idW, _ := windows.UTF16PtrFromString(instanceID)
	var devInst uint32
	r, _, _ := procCMLocateDevNodeW.Call(
		uintptr(unsafe.Pointer(&devInst)),
		uintptr(unsafe.Pointer(idW)),
		0,
	)
	if r != crSuccess {
		return 0, fmt.Errorf("CM_Locate_DevNodeW: 0x%x", r)
	}
	return devInst, nil
}

func cmGetParent(devInst uint32) (uint32, error) {
	var parent uint32
	r, _, _ := procCMGetParent.Call(
		uintptr(unsafe.Pointer(&parent)),
		uintptr(devInst),
		0,
	)
	if r != crSuccess {
		return 0, fmt.Errorf("CM_Get_Parent: 0x%x", r)
	}
	return parent, nil
}

func cmGetDeviceID(devInst uint32) (string, error) {
	var buf [1024]uint16
	r, _, _ := procCMGetDeviceIDW.Call(
		uintptr(devInst),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if r != crSuccess {
		return "", fmt.Errorf("CM_Get_Device_IDW: 0x%x", r)
	}
	return windows.UTF16ToString(buf[:]), nil
}

func cmGetAddress(devInst uint32) (uint32, error) {
	var val, valType, size uint32
	size = 4
	r, _, _ := procCMGetDevNodeRegistryPropW.Call(
		uintptr(devInst),
		cmDRPAddress,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&val)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != crSuccess {
		return 0, fmt.Errorf("CM_Get_DevNode_Registry_PropertyW(ADDRESS): 0x%x", r)
	}
	return val, nil
}

// getAllInterfacePaths returns all device interface paths for the given GUID.
func getAllInterfacePaths(guid windows.GUID) []string {
	var size uint32
	procCMGetDeviceInterfaceListSizeW.Call(
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&guid)),
		0,
		0,
	)
	if size <= 1 {
		return nil
	}
	buf := make([]uint16, size)
	r, _, _ := procCMGetDeviceInterfaceListW.Call(
		uintptr(unsafe.Pointer(&guid)),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		0,
	)
	if r != crSuccess {
		return nil
	}
	var paths []string
	start := 0
	for i, w := range buf {
		if w == 0 {
			if i > start {
				paths = append(paths, windows.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}
	return paths
}

// hubInterfacePath returns the device interface path for instanceID if it has
// a USB hub interface; used only for the legacy FindUSBPcapForPort path.
func hubInterfacePath(instanceID string) string {
	idW, _ := windows.UTF16PtrFromString(instanceID)
	var size uint32
	r, _, _ := procCMGetDeviceInterfaceListSizeW.Call(
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&guidUSBHub)),
		uintptr(unsafe.Pointer(idW)),
		0,
	)
	if r != crSuccess || size <= 1 {
		return ""
	}
	buf := make([]uint16, size)
	r, _, _ = procCMGetDeviceInterfaceListW.Call(
		uintptr(unsafe.Pointer(&guidUSBHub)),
		uintptr(unsafe.Pointer(idW)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		0,
	)
	if r != crSuccess {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// ─── USB hub FDO access (via host-controller IOCTL path) ─────────────────────

// openFDO opens a device for USB hub IOCTLs using FILE_SHARE_WRITE (matches USBView).
func openFDO(path string) (windows.Handle, error) {
	pathW, _ := windows.UTF16PtrFromString(path)
	return windows.CreateFile(pathW,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
}

// getRootHubPath sends IOCTL_USB_GET_ROOT_HUB_NAME to a host controller and
// returns the root hub FDO path (\\.\-prefixed, ready for CreateFile).
func getRootHubPath(hcPath string) string {
	h, err := openFDO(hcPath)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var buf [2048]byte
	var returned uint32
	if err := windows.DeviceIoControl(h, ioctlUSBGetRootHubName,
		nil, 0, &buf[0], uint32(len(buf)), &returned, nil); err != nil || returned < 6 {
		return ""
	}
	// USB_ROOT_HUB_NAME: ULONG ActualLength, WCHAR RootHubName[...]
	nameWords := (returned - 4) / 2
	wchars := make([]uint16, nameWords)
	for i := range wchars {
		wchars[i] = binary.LittleEndian.Uint16(buf[4+i*2 : 6+i*2])
	}
	name := windows.UTF16ToString(wchars)
	if name == "" {
		return ""
	}
	return `\\.\` + name
}

// hubPortCount sends IOCTL_USB_GET_NODE_INFORMATION and returns the port count.
// USB_NODE_INFORMATION: ULONG NodeType at [0], USB_HUB_DESCRIPTOR at [4],
// bNumberOfPorts is the 3rd byte of USB_HUB_DESCRIPTOR → offset 6 overall.
func hubPortCount(hubPath string) uint32 {
	h, err := openFDO(hubPath)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)

	var buf [256]byte
	var returned uint32
	if err := windows.DeviceIoControl(h, ioctlUSBGetNodeInfo,
		nil, 0, &buf[0], uint32(len(buf)), &returned, nil); err != nil || returned < 7 {
		return 0
	}
	return uint32(buf[6])
}


// probeConnInfo probes a hub port for VID, PID, USB device address, and hub flag.
//
// Tries IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX (0x00220450) first.
// On Windows 11 systems where that IOCTL returns only 4 bytes, falls back to
// IOCTL_USB_GET_NODE_CONNECTION_INFORMATION (0x0022040C, non-EX).
//
// Non-EX struct layout (35-byte base, no padding before DeviceAddress):
//
//	[0:4]   ConnectionIndex
//	[4:22]  USB_DEVICE_DESCRIPTOR  — idVendor at [12], idProduct at [14]
//	[22]    CurrentConfigurationValue
//	[23]    LowSpeed (BOOLEAN)
//	[24]    DeviceIsHub (BOOLEAN)
//	[25:27] DeviceAddress (USHORT, no alignment padding — sizeof confirmed = 35)
//
// EX struct layout (36-byte base, 1-byte pad at [25] before DeviceAddress):
//
//	[24]    DeviceIsHub
//	[25]    (padding)
//	[26:28] DeviceAddress
func probeConnInfo(hubPath string, portNum uint32) (vid, pid, addr uint16, isHub bool) {
	h, err := openFDO(hubPath)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)

	var buf [4096]byte
	binary.LittleEndian.PutUint32(buf[0:4], portNum)
	var returned uint32

	// Try _EX variant first.
	useEX := false
	if err := windows.DeviceIoControl(h, ioctlUSBGetNodeConnInfoEx,
		&buf[0], uint32(len(buf)), &buf[0], uint32(len(buf)), &returned, nil); err == nil && returned >= 28 {
		useEX = true
	} else {
		// Fall back to non-EX.
		binary.LittleEndian.PutUint32(buf[0:4], portNum)
		if err2 := windows.DeviceIoControl(h, ioctlUSBGetNodeConnInfo,
			&buf[0], uint32(len(buf)), &buf[0], uint32(len(buf)), &returned, nil); err2 != nil || returned < 28 {
			return
		}
	}

	vid = binary.LittleEndian.Uint16(buf[12:14])
	pid = binary.LittleEndian.Uint16(buf[14:16])
	isHub = buf[24] != 0
	if useEX {
		addr = binary.LittleEndian.Uint16(buf[26:28]) // EX: 1-byte pad at [25]
	} else {
		addr = binary.LittleEndian.Uint16(buf[25:27]) // non-EX: no padding
	}
	return
}

// scanHub probes all ports on hubPath for wantVID/wantPID.
// Returns the USB device address when found, 0 otherwise.
// Does NOT recurse — caller handles child hubs separately.
func scanHub(hubPath string, wantVID, wantPID uint16) uint16 {
	nPorts := hubPortCount(hubPath)
	if nPorts == 0 || nPorts > 255 {
		return 0
	}
	for port := uint32(1); port <= nPorts; port++ {
		vid, pid, addr, _ := probeConnInfo(hubPath, port)
		if vid == wantVID && pid == wantPID && addr != 0 {
			return addr
		}
	}
	return 0
}

// parseVIDPID extracts VID and PID from a device ID like "USB\VID_0403&PID_6015\...".
func parseVIDPID(deviceID string) (vid, pid uint16) {
	upper := strings.ToUpper(deviceID)
	if i := strings.Index(upper, "VID_"); i >= 0 && i+8 <= len(upper) {
		if v, err := strconv.ParseUint(upper[i+4:i+8], 16, 16); err == nil {
			vid = uint16(v)
		}
	}
	if i := strings.Index(upper, "PID_"); i >= 0 && i+8 <= len(upper) {
		if v, err := strconv.ParseUint(upper[i+4:i+8], 16, 16); err == nil {
			pid = uint16(v)
		}
	}
	return
}

// ─── Public: real USB device address ─────────────────────────────────────────

// FindUSBDeviceNumber returns the USB device address (1-127) assigned by the
// host controller to the USB device corresponding to instanceID.
//
// Strategy:
//  1. Walk the CM tree from instanceID up to the USB\VID_xxxx&PID_xxxx node.
//  2. Parse VID/PID from that node's device ID.
//  3. Collect hub FDO paths two ways:
//     a. HC → IOCTL_USB_GET_ROOT_HUB_NAME (guaranteed FDO, works on all Windows).
//     b. GUID_DEVINTERFACE_USB_HUB enumeration (catches child hubs not reachable
//        via IOCTL_USB_GET_NODE_CONNECTION_NAME, which can fail on Win11 USB4 hubs).
//  4. Probe every port of every unique hub for VID/PID match.
func FindUSBDeviceNumber(instanceID string) (uint16, error) {
	// Fast path: VID/PID may be encoded directly in the instance ID.
	// Works for both "USB\VID_0403&PID_6015\..." and "FTDIBUS\VID_0403+PID_6015+...\...".
	wantVID, wantPID := parseVIDPID(instanceID)

	if wantVID == 0 {
		// Slow path: walk the CM device tree to find the USB\VID_ ancestor.
		devInst, err := cmLocateDevNode(instanceID)
		if err != nil {
			return 0, fmt.Errorf("locate %s: %w", instanceID, err)
		}
		cur := devInst
		for range [16]struct{}{} {
			parent, pErr := cmGetParent(cur)
			if pErr != nil {
				break
			}
			id, iErr := cmGetDeviceID(parent)
			if iErr != nil {
				break
			}
			upper := strings.ToUpper(id)
			if strings.HasPrefix(upper, `USB\VID_`) && !strings.Contains(upper, "ROOT_HUB") {
				wantVID, wantPID = parseVIDPID(id)
				break
			}
			cur = parent
		}
		if wantVID == 0 {
			return 0, fmt.Errorf("cannot determine VID/PID for %s", instanceID)
		}
	}

	fmt.Printf("[info] scanning USB hubs for VID_%04X&PID_%04X\n", wantVID, wantPID)

	// Collect unique hub paths: root hubs (via HC) + all hub interfaces.
	seen := make(map[string]bool)
	var hubPaths []string
	addHub := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			hubPaths = append(hubPaths, p)
		}
	}

	// Root hubs via host controllers (these are always FDO paths).
	for _, hcPath := range getAllInterfacePaths(guidUSBHostController) {
		addHub(getRootHubPath(hcPath))
	}

	// All hub interfaces (catches child hubs the tree walk misses).
	for _, p := range getAllInterfacePaths(guidUSBHub) {
		addHub(p)
	}

	for _, hubPath := range hubPaths {
		if addr := scanHub(hubPath, wantVID, wantPID); addr != 0 {
			fmt.Printf("[info] USB device address: %d\n", addr)
			return addr, nil
		}
	}

	return 0, fmt.Errorf("VID_%04X&PID_%04X not found across %d hub paths",
		wantVID, wantPID, len(hubPaths))
}

// ─── Root-hub finder ─────────────────────────────────────────────────────────

func findRootHubID(instanceID string) string {
	devInst, err := cmLocateDevNode(instanceID)
	if err != nil {
		return ""
	}
	for range [16]struct{}{} {
		parent, err := cmGetParent(devInst)
		if err != nil {
			break
		}
		id, err := cmGetDeviceID(parent)
		if err != nil {
			break
		}
		if strings.Contains(strings.ToUpper(id), "ROOT_HUB") {
			return id
		}
		devInst = parent
	}
	return ""
}

func instanceKey(deviceID string) string {
	parts := strings.Split(deviceID, `\`)
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

// ─── USBPcap hub symlink IOCTL ────────────────────────────────────────────────

// IOCTL_USBPCAP_GET_HUB_SYMLINK = CTL_CODE(0xf2a0, 0x805, BUFFERED, READ)
const ioctlGetHubSymlink uint32 = 0xf2a06014

func usbpcapHubSymlink(pcapPath string) (string, error) {
	pathW, _ := windows.UTF16PtrFromString(pcapPath)
	h, err := windows.CreateFile(pathW,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", pcapPath, err)
	}
	defer windows.CloseHandle(h)

	var buf [2048]byte
	var returned uint32
	err = windows.DeviceIoControl(h, ioctlGetHubSymlink,
		nil, 0, &buf[0], uint32(len(buf)), &returned, nil)
	if err != nil || returned < 2 {
		return "", fmt.Errorf("IOCTL_USBPCAP_GET_HUB_SYMLINK: %w", err)
	}
	n := int(returned / 2)
	wbuf := make([]uint16, n)
	for i := range wbuf {
		wbuf[i] = uint16(buf[i*2]) | uint16(buf[i*2+1])<<8
	}
	return windows.UTF16ToString(wbuf), nil
}

// ─── Public API ──────────────────────────────────────────────────────────────

// FindUSBPcapForPort returns the \\.\USBPcapN path whose root hub matches the
// one the given COM port is attached to.
func FindUSBPcapForPort(portName string, pcapDevs []string) string {
	info, err := FindCOMPort(portName)
	if err != nil {
		return ""
	}
	rootHubID := findRootHubID(info.InstanceID)
	if rootHubID == "" {
		return ""
	}
	key := instanceKey(rootHubID)
	if key == "" {
		return ""
	}
	for _, dev := range pcapDevs {
		symlink, err := usbpcapHubSymlink(dev)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(symlink), key) {
			return dev
		}
	}
	return ""
}

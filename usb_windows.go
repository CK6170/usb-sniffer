package main

// USB device enumeration via SetupDi APIs.
// Maps COM port names (e.g. "COM3") to USB device instance IDs so we can
// correlate ETW events to the right port.

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	setupapi                         = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiGetClassDevsW         = setupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiEnumDeviceInfo        = setupapi.NewProc("SetupDiEnumDeviceInfo")
	procSetupDiGetDeviceRegistryPropW = setupapi.NewProc("SetupDiGetDeviceRegistryPropertyW")
	procSetupDiGetDeviceInstanceIdW  = setupapi.NewProc("SetupDiGetDeviceInstanceIdW")
	procSetupDiDestroyDeviceInfoList = setupapi.NewProc("SetupDiDestroyDeviceInfoList")
)

const (
	DIGCF_PRESENT    = 0x00000002
	DIGCF_ALLCLASSES = 0x00000004
	SPDRP_FRIENDLYNAME = 12
	SPDRP_HARDWAREID   = 1
)

// GUID for Ports device class (COM & LPT ports)
var guidDevclassPorts = windows.GUID{
	Data1: 0x4D36E978,
	Data2: 0xE325,
	Data3: 0x11CE,
	Data4: [8]byte{0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18},
}

type SP_DEVINFO_DATA struct {
	CbSize    uint32
	ClassGuid windows.GUID
	DevInst   uint32
	Reserved  uintptr
}

// COMPortInfo holds the COM port name and its USB hardware ID.
type COMPortInfo struct {
	Port       string // "COM3"
	FriendlyName string
	HardwareID   string // e.g. "USB\VID_067B&PID_2303"
	InstanceID   string // full PnP instance path
}

// EnumerateCOMPorts returns all currently present COM ports with their USB info.
func EnumerateCOMPorts() ([]COMPortInfo, error) {
	hDevInfo, _, err := procSetupDiGetClassDevsW.Call(
		uintptr(unsafe.Pointer(&guidDevclassPorts)),
		0,
		0,
		DIGCF_PRESENT,
	)
	if hDevInfo == ^uintptr(0) {
		return nil, fmt.Errorf("SetupDiGetClassDevs: %v", err)
	}
	defer procSetupDiDestroyDeviceInfoList.Call(hDevInfo)

	var ports []COMPortInfo
	for i := uint32(0); ; i++ {
		var devInfo SP_DEVINFO_DATA
		devInfo.CbSize = uint32(unsafe.Sizeof(devInfo))

		r, _, _ := procSetupDiEnumDeviceInfo.Call(
			hDevInfo,
			uintptr(i),
			uintptr(unsafe.Pointer(&devInfo)),
		)
		if r == 0 {
			break
		}

		friendly := getRegistryProperty(hDevInfo, &devInfo, SPDRP_FRIENDLYNAME)
		hwid := getRegistryProperty(hDevInfo, &devInfo, SPDRP_HARDWAREID)
		instanceID := getInstanceID(hDevInfo, &devInfo)

		port := extractCOMPort(friendly)
		if port == "" {
			continue
		}

		ports = append(ports, COMPortInfo{
			Port:         port,
			FriendlyName: friendly,
			HardwareID:   hwid,
			InstanceID:   instanceID,
		})
	}
	return ports, nil
}

// FindCOMPort returns info for a specific port name, or nil if not found.
func FindCOMPort(name string) (*COMPortInfo, error) {
	name = strings.ToUpper(strings.TrimSpace(name))
	ports, err := EnumerateCOMPorts()
	if err != nil {
		return nil, err
	}
	for i := range ports {
		if ports[i].Port == name {
			return &ports[i], nil
		}
	}
	return nil, fmt.Errorf("COM port %s not found", name)
}

func getRegistryProperty(hDevInfo uintptr, devInfo *SP_DEVINFO_DATA, prop uint32) string {
	var buf [4096]uint16
	var dataType, size uint32
	procSetupDiGetDeviceRegistryPropW.Call(
		hDevInfo,
		uintptr(unsafe.Pointer(devInfo)),
		uintptr(prop),
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&size)),
	)
	return windows.UTF16ToString(buf[:])
}

func getInstanceID(hDevInfo uintptr, devInfo *SP_DEVINFO_DATA) string {
	var buf [1024]uint16
	var size uint32
	procSetupDiGetDeviceInstanceIdW.Call(
		hDevInfo,
		uintptr(unsafe.Pointer(devInfo)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&size)),
	)
	return windows.UTF16ToString(buf[:])
}

// extractCOMPort pulls "COM3" out of a friendly name like
// "USB Serial Port (COM3)" or "Communications Port (COM1)".
func extractCOMPort(friendly string) string {
	s := strings.ToUpper(friendly)
	start := strings.Index(s, "(COM")
	if start < 0 {
		return ""
	}
	end := strings.Index(s[start:], ")")
	if end < 0 {
		return ""
	}
	return strings.TrimLeft(s[start+1:start+end], " ")
}

// usbBusPrefixes covers the bus enumerator prefixes used by common USB-to-serial
// chipsets. FTDI uses its own "FTDIBUS\" enumerator; CP210x uses "SILABSER\";
// standard CDC/ACM devices use "USB\".
var usbBusPrefixes = []string{
	`USB\`,      // standard Windows CDC/ACM
	`FTDIBUS\`,  // FTDI FT232/FT2232/FT4232 etc.
	`SILABSER\`, // Silicon Labs CP210x
	`USBSER\`,   // generic usbser.sys
	`CH341\`,    // WCH CH340/CH341
	`PROLIFIC\`, // Prolific PL2303
}

// isUSBDevice returns true when the hardware ID matches a known USB serial bus.
func isUSBDevice(hwid string) bool {
	upper := strings.ToUpper(hwid)
	for _, prefix := range usbBusPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// isAdmin checks whether the current process has administrator privileges.
func isAdmin() bool {
	// SID for Administrators group.
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// openDeviceInterface opens a raw file handle to a COM port (read-only, no
// exclusive hold) using FILE_SHARE_READ|FILE_SHARE_WRITE so the owning app
// keeps working. We use this only to verify the device is accessible.
func openDeviceInterface(port string) (syscall.Handle, error) {
	path := `\\.\` + port
	pathW, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	h, err := syscall.CreateFile(
		pathW,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	return h, err
}

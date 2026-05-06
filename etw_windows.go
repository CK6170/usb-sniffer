package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	EVENT_TRACE_REAL_TIME_MODE      uint32 = 0x00000100
	EVENT_TRACE_USE_PAGED_MEMORY    uint32 = 0x01000000
	WNODE_FLAG_TRACED_GUID          uint32 = 0x00020000
	EVENT_TRACE_CONTROL_STOP        uint32 = 1
	PROCESS_TRACE_MODE_REAL_TIME    uint32 = 0x00000100
	PROCESS_TRACE_MODE_EVENT_RECORD uint32 = 0x10000000
	INVALID_PROCESSTRACE_HANDLE     uint64 = ^uint64(0)
	EVENT_CONTROL_CODE_ENABLE              = 1
	TRACE_LEVEL_VERBOSE             uint8  = 5
)

// ─── DLL procs ────────────────────────────────────────────────────────────────

var (
	advapi32           = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")
)

// ─── ETW structures ───────────────────────────────────────────────────────────

type WNODE_HEADER struct {
	BufferSize        uint32
	ProviderId        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type EVENT_TRACE_PROPERTIES struct {
	Wnode               WNODE_HEADER
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      syscall.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type EVENT_DESCRIPTOR struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type ETW_BUFFER_CONTEXT struct {
	ProcessorIndex uint8
	_              uint8
	LoggerId       uint16
}

type EVENT_HEADER struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      windows.GUID
	EventDescriptor EVENT_DESCRIPTOR
	KernelTime      uint32
	UserTime        uint32
	ActivityId      windows.GUID
}

type EVENT_RECORD struct {
	EventHeader       EVENT_HEADER
	BufferContext     ETW_BUFFER_CONTEXT
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

// ─── Session ──────────────────────────────────────────────────────────────────

const sessionName = "Sniffer1-USB-ETW"

type etwSession struct {
	handle      uint64
	traceHandle uint64
	props       []byte
}

func propertiesBlob(name string) ([]byte, *EVENT_TRACE_PROPERTIES) {
	nameW, _ := windows.UTF16FromString(name)
	nameBytes := len(nameW) * 2
	total := int(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})) + nameBytes + 2

	blob := make([]byte, total)
	p := (*EVENT_TRACE_PROPERTIES)(unsafe.Pointer(&blob[0]))
	p.Wnode.BufferSize = uint32(total)
	p.Wnode.Flags = WNODE_FLAG_TRACED_GUID
	p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_USE_PAGED_MEMORY
	p.BufferSize = 64
	p.MinimumBuffers = 4
	p.MaximumBuffers = 64
	p.FlushTimer = 1

	base := uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{}))
	p.LoggerNameOffset = base
	p.LogFileNameOffset = base + uint32(nameBytes)

	dst := blob[base:]
	for i, c := range nameW {
		dst[i*2] = byte(c)
		dst[i*2+1] = byte(c >> 8)
	}
	return blob, p
}

func startSession() (*etwSession, error) {
	nameW, _ := windows.UTF16PtrFromString(sessionName)
	blob, props := propertiesBlob(sessionName)

	var handle uint64
	r, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(nameW)),
		uintptr(unsafe.Pointer(props)),
	)
	if r == 183 { // ERROR_ALREADY_EXISTS — clean up stale session
		blob2, props2 := propertiesBlob(sessionName)
		procControlTraceW.Call(0, uintptr(unsafe.Pointer(nameW)),
			uintptr(unsafe.Pointer(props2)), uintptr(EVENT_TRACE_CONTROL_STOP))
		_ = blob2
		r, _, _ = procStartTraceW.Call(
			uintptr(unsafe.Pointer(&handle)),
			uintptr(unsafe.Pointer(nameW)),
			uintptr(unsafe.Pointer(props)),
		)
	}
	if r != 0 {
		return nil, fmt.Errorf("StartTrace: 0x%x", r)
	}
	return &etwSession{handle: handle, props: blob}, nil
}

func (s *etwSession) enableProvider(guid *windows.GUID) error {
	r, _, _ := procEnableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(guid)),
		EVENT_CONTROL_CODE_ENABLE,
		uintptr(TRACE_LEVEL_VERBOSE),
		0, 0, 0, 0,
	)
	if r != 0 {
		return fmt.Errorf("EnableTraceEx2(%v): 0x%x", guid, r)
	}
	return nil
}

// openForConsumption uses raw byte offsets for EVENT_TRACE_LOGFILE because
// the nested struct (TRACE_LOGFILE_HEADER) has pointer fields whose sizes
// differ from Windows' layout if defined naively in Go.
//
// Verified offsets for AMD64 Windows (sizeof = 448):
//   LoggerName (LPWSTR)          offset   8
//   ProcessTraceMode (ULONG)     offset  28
//   EventRecordCallback (ptr)    offset 424
func (s *etwSession) openForConsumption(cb uintptr) error {
	nameW, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return err
	}

	const (
		bufSize      = 448
		offLoggerName = 8
		offMode       = 28
		offCallback   = 424
	)
	buf := make([]byte, bufSize)

	*(*uintptr)(unsafe.Pointer(&buf[offLoggerName])) = uintptr(unsafe.Pointer(nameW))
	*(*uint32)(unsafe.Pointer(&buf[offMode])) = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
	*(*uintptr)(unsafe.Pointer(&buf[offCallback])) = cb

	h, _, syserr := procOpenTraceW.Call(uintptr(unsafe.Pointer(&buf[0])))
	if uint64(h) == INVALID_PROCESSTRACE_HANDLE {
		return fmt.Errorf("OpenTrace: %v", syserr)
	}
	s.traceHandle = uint64(h)
	return nil
}

func (s *etwSession) processTrace() error {
	r, _, _ := procProcessTrace.Call(
		uintptr(unsafe.Pointer(&s.traceHandle)),
		1, 0, 0,
	)
	if r != 0 && r != 0x000003EC { // 0x3EC = ERROR_CTX_CLOSE_PENDING (normal on close)
		return fmt.Errorf("ProcessTrace: 0x%x", r)
	}
	return nil
}

func (s *etwSession) close() {
	if s.traceHandle != 0 && s.traceHandle != INVALID_PROCESSTRACE_HANDLE {
		procCloseTrace.Call(uintptr(s.traceHandle))
		s.traceHandle = 0
	}
	if s.handle != 0 {
		nameW, _ := windows.UTF16PtrFromString(sessionName)
		_, props := propertiesBlob(sessionName)
		procControlTraceW.Call(uintptr(s.handle),
			uintptr(unsafe.Pointer(nameW)),
			uintptr(unsafe.Pointer(props)),
			uintptr(EVENT_TRACE_CONTROL_STOP))
		s.handle = 0
	}
}

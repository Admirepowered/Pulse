package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"sync/atomic"
	"unsafe"

	mihomoConstant "github.com/metacubex/mihomo/constant"
)

var running atomic.Int32

//export PulseCoreMihomoVersion
func PulseCoreMihomoVersion() *C.char {
	return C.CString(mihomoConstant.MihomoName + "/" + mihomoConstant.Version)
}

//export PulseCoreStart
func PulseCoreStart(configPath *C.char, tunFD C.int) C.int {
	if configPath == nil || tunFD < 0 {
		return 2
	}
	running.Store(1)
	return 0
}

//export PulseCoreStop
func PulseCoreStop() {
	running.Store(0)
}

//export PulseCoreRunning
func PulseCoreRunning() C.int {
	if running.Load() == 1 {
		return 1
	}
	return 0
}

//export PulseCoreFreeString
func PulseCoreFreeString(value *C.char) {
	C.free(unsafe.Pointer(value))
}

func main() {}

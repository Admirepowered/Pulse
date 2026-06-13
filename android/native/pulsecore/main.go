package main

/*
#include <jni.h>
#include <stdlib.h>
#include <string.h>

static char* pulse_jstring_to_c(JNIEnv* env, jstring value) {
	if (value == NULL) {
		return NULL;
	}
	const char* chars = (*env)->GetStringUTFChars(env, value, 0);
	if (chars == NULL) {
		return NULL;
	}
	char* out = strdup(chars);
	(*env)->ReleaseStringUTFChars(env, value, chars);
	return out;
}

static jstring pulse_new_jstring(JNIEnv* env, const char* value) {
	if (value == NULL) {
		value = "";
	}
	return (*env)->NewStringUTF(env, value);
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/mihomo/config"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"gopkg.in/yaml.v3"
)

var running atomic.Int32
var lastError atomic.Value

//export PulseCoreMihomoVersion
func PulseCoreMihomoVersion() *C.char {
	return C.CString(mihomoConstant.MihomoName + "/" + mihomoConstant.Version)
}

//export PulseCoreStart
func PulseCoreStart(configPath *C.char, tunFD C.int) C.int {
	if configPath == nil || tunFD < 0 {
		return 2
	}
	return C.int(startMihomo(C.GoString(configPath), filepath.Dir(C.GoString(configPath)), int(tunFD), false))
}

//export PulseCoreStop
func PulseCoreStop() {
	stopMihomo()
}

//export PulseCoreSetMode
func PulseCoreSetMode(mode *C.char) C.int {
	if mode == nil {
		return 2
	}
	return C.int(setMode(C.GoString(mode)))
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

//export Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeVersion
func Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeVersion(env *C.JNIEnv, obj C.jobject) C.jstring {
	version := mihomoConstant.MihomoName + "/" + mihomoConstant.Version
	cVersion := C.CString(version)
	defer C.free(unsafe.Pointer(cVersion))
	_ = obj
	return C.pulse_new_jstring(env, cVersion)
}

//export Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeStart
func Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeStart(env *C.JNIEnv, obj C.jobject, configPath C.jstring, homeDir C.jstring, tunFD C.jint, allowLan C.jboolean) C.jint {
	_ = obj
	cConfigPath := C.pulse_jstring_to_c(env, configPath)
	defer C.free(unsafe.Pointer(cConfigPath))
	cHomeDir := C.pulse_jstring_to_c(env, homeDir)
	defer C.free(unsafe.Pointer(cHomeDir))
	if cConfigPath == nil || cHomeDir == nil {
		setLastError(fmt.Errorf("config path or home dir is empty"))
		return 2
	}
	return C.jint(startMihomo(C.GoString(cConfigPath), C.GoString(cHomeDir), int(tunFD), allowLan != 0))
}

//export Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeStop
func Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeStop(env *C.JNIEnv, obj C.jobject) {
	_, _ = env, obj
	stopMihomo()
}

//export Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeRunning
func Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeRunning(env *C.JNIEnv, obj C.jobject) C.jboolean {
	_, _ = env, obj
	if running.Load() == 1 {
		return 1
	}
	return 0
}

//export Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeSetMode
func Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeSetMode(env *C.JNIEnv, obj C.jobject, mode C.jstring) C.jint {
	_ = obj
	cMode := C.pulse_jstring_to_c(env, mode)
	defer C.free(unsafe.Pointer(cMode))
	if cMode == nil {
		setLastError(fmt.Errorf("mode is empty"))
		return 2
	}
	return C.jint(setMode(C.GoString(cMode)))
}

//export Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeLastError
func Java_com_admirepowered_pulse_core_PulseCoreBridge_nativeLastError(env *C.JNIEnv, obj C.jobject) C.jstring {
	value, _ := lastError.Load().(string)
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	_ = obj
	return C.pulse_new_jstring(env, cValue)
}

func startMihomo(configPath string, homeDir string, tunFD int, allowLan bool) int {
	if configPath == "" || homeDir == "" || tunFD < 0 {
		setLastError(fmt.Errorf("invalid start arguments"))
		return 2
	}

	mihomoConstant.SetHomeDir(homeDir)
	mihomoConstant.SetConfig(configPath)
	if err := config.Init(homeDir); err != nil {
		setLastError(err)
		return 3
	}

	configBytes, err := androidConfigBytes(configPath, tunFD, allowLan)
	if err != nil {
		setLastError(err)
		return 4
	}
	cfg, err := executor.ParseWithBytes(configBytes)
	if err != nil {
		setLastError(err)
		return 5
	}
	stopMihomo()
	hub.ApplyConfig(cfg)
	running.Store(1)
	setLastError(nil)
	return 0
}

func stopMihomo() {
	if running.Swap(0) == 1 {
		executor.Shutdown()
	}
}

func setMode(modeName string) int {
	var mode tunnel.TunnelMode
	if err := mode.UnmarshalText([]byte(modeName)); err != nil {
		setLastError(err)
		return 2
	}
	tunnel.SetMode(mode)
	setLastError(nil)
	return 0
}

func androidConfigBytes(configPath string, tunFD int, allowLan bool) ([]byte, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	root := map[string]any{}
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	tun, _ := root["tun"].(map[string]any)
	if tun == nil {
		tun = map[string]any{}
	}
	tun["enable"] = true
	tun["stack"] = "gvisor"
	tun["auto-route"] = false
	tun["auto-redirect"] = false
	tun["auto-detect-interface"] = false
	tun["strict-route"] = false
	tun["mtu"] = 9000
	tun["file-descriptor"] = tunFD
	tun["dns-hijack"] = []string{"any:53", "tcp://any:53"}
	root["tun"] = tun
	if _, ok := root["mode"]; !ok {
		root["mode"] = "rule"
	}
	if _, ok := root["log-level"]; !ok {
		root["log-level"] = "silent"
	}
	root["external-controller"] = "127.0.0.1:9090"
	root["allow-lan"] = allowLan
	return yaml.Marshal(root)
}

func setLastError(err error) {
	if err == nil {
		lastError.Store("")
		return
	}
	lastError.Store(err.Error())
}

func main() {}

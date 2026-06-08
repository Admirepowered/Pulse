//go:build windows

package pulse

import (
	"strings"
	"testing"
)

func TestBuildAdminRelaunchScriptOmitsEmptyArgumentList(t *testing.T) {
	script := buildAdminRelaunchScript(`E:\Tools\Pulse\Pulse.exe`, `E:\Tools\Pulse`, nil, 1234)
	if strings.Contains(script, "$args = @(") {
		t.Fatalf("empty args should not declare an args list, got %q", script)
	}
	if !strings.Contains(script, "Verb RunAs") {
		t.Fatalf("script should request elevation, got %q", script)
	}
	if !strings.Contains(script, "Stop-Process") {
		t.Fatalf("script should stop the calling process, got %q", script)
	}
	if !strings.Contains(script, "Remove-Item") {
		t.Fatalf("script should clean itself up, got %q", script)
	}
}

func TestBuildAdminRelaunchScriptIncludesArguments(t *testing.T) {
	script := buildAdminRelaunchScript(`E:\Tools\Pulse\Pulse.exe`, `E:\Tools\Pulse`, []string{"clash://install-config?url=https%3A%2F%2Fexample.com"}, 1234)
	if !strings.Contains(script, "$args = @(") {
		t.Fatalf("args should declare the args list, got %q", script)
	}
	if !strings.Contains(script, "install-config") {
		t.Fatalf("args should be preserved, got %q", script)
	}
	if !strings.Contains(script, "Verb RunAs") {
		t.Fatalf("script should still request elevation, got %q", script)
	}
}

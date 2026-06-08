package pulse

import (
	"strings"
	"testing"
)

func TestMergeRuntimeConfigWritesTunSettings(t *testing.T) {
	settings := defaultSettings()
	settings.Secret = "secret"
	settings.TunEnabled = true
	settings.TunStack = "mixed"
	settings.TunDevice = "utun0"
	settings.TunStrictRoute = true
	settings.TunInet6Address = "fdfe:dcba:9876::1/126"
	settings.TunRouteAddress = []string{"0.0.0.0/1", "128.0.0.0/1"}
	settings.TunIncludeIF = []string{"eth0"}
	settings.TunIncludeUID = []int{0}

	output, err := mergeRuntimeConfig([]byte("proxies: []\nproxy-groups: []\nrules: []\n"), settings, "127.0.0.1:9090", nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(output)
	for _, want := range []string{
		"ipv6: true",
		"tun:",
		"enable: true",
		"stack: mixed",
		"device: utun0",
		"strict-route: true",
		"inet6-address: fdfe:dcba:9876::1/126",
		"route-address:",
		"include-interface:",
		"include-uid:",
		"- 0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("runtime config missing %q:\n%s", want, text)
		}
	}
}

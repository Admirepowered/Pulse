//go:build windows && pulse_service_embed_mihomo

package pulse

func serviceHelperHasEmbeddedCore() bool {
	return true
}

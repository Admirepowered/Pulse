//go:build !windows || (windows && !pulse_service_embed_mihomo)

package pulse

func serviceHelperHasEmbeddedCore() bool {
	return false
}

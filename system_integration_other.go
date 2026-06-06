//go:build !windows

package main

func setAutoStart(enabled bool) error {
	return nil
}

func configureSystemProxy(settings Settings, enabled bool) error {
	return nil
}

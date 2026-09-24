//go:build !windows

package main

// runNativeWindow has no native window implementation outside Windows, so the
// caller falls back to a dedicated app-mode browser window.
func runNativeWindow(url string) bool { return false }

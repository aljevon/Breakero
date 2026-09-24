//go:build windows

package main

import (
	"runtime"

	webview2 "github.com/jchv/go-webview2"
)

// runNativeWindow opens Breakero as a genuine native desktop window on Windows
// using the WebView2 runtime (the Edge engine that ships with Windows 10/11).
// This is our own process with its own window and taskbar entry: no browser
// chrome, no separate browser. It navigates the window to the local app URL.
//
// It returns false when a native window could not be created (for example the
// WebView2 runtime is not installed), so the caller can fall back to opening a
// dedicated app-mode browser window instead.
func runNativeWindow(url string) bool {
	// WebView2 must own the main OS thread for its message loop.
	runtime.LockOSThread()

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "Breakero",
			Width:  1080,
			Height: 820,
			IconId: 2, // app icon from the embedded resource
			Center: true,
		},
	})
	if w == nil {
		return false
	}
	defer w.Destroy()
	w.Navigate(url)
	w.Run() // blocks until the window is closed
	return true
}

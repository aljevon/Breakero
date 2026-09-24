//go:build windows

package main

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

//go:embed breakero.ico
var icoData []byte

// runNativeWindow opens Breakero as a genuine native desktop window on Windows
// using the WebView2 runtime (the Edge engine that ships with Windows 10/11).
// This is our own process with its own window and taskbar entry: no browser
// chrome, no separate browser. It navigates the window to the local app URL.
//
// It returns false when a native window could not be created (for example the
// WebView2 runtime is not installed), so the caller can fall back to a
// dedicated app-mode browser window instead.
func runNativeWindow(url string) bool {
	// WebView2 must own the main OS thread for its message loop.
	runtime.LockOSThread()

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "Breakero",
			Width:  1120,
			Height: 840,
			Center: true,
		},
	})
	if w == nil {
		return false
	}
	defer w.Destroy()

	setWindowIcon(uintptr(w.Window()))
	w.Navigate(url)
	w.Run() // blocks until the window is closed
	return true
}

// setWindowIcon puts the Breakero icon on the window and taskbar by loading the
// embedded .ico at runtime and sending WM_SETICON. Done this way it does not
// depend on a specific resource id in the compiled binary.
func setWindowIcon(hwnd uintptr) {
	if hwnd == 0 || len(icoData) == 0 {
		return
	}
	path := filepath.Join(os.TempDir(), "breakero-window.ico")
	if err := os.WriteFile(path, icoData, 0o644); err != nil {
		return
	}
	p16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	user32 := syscall.NewLazyDLL("user32.dll")
	loadImage := user32.NewProc("LoadImageW")
	sendMessage := user32.NewProc("SendMessageW")

	const (
		imageIcon      = 1
		lrLoadFromFile = 0x00000010
		lrDefaultSize  = 0x00000040
		wmSetIcon      = 0x0080
		iconSmall      = 0
		iconBig        = 1
	)

	if hBig, _, _ := loadImage.Call(0, uintptr(unsafe.Pointer(p16)), imageIcon,
		0, 0, lrLoadFromFile|lrDefaultSize); hBig != 0 {
		sendMessage.Call(hwnd, wmSetIcon, iconBig, hBig)
	}
	if hSmall, _, _ := loadImage.Call(0, uintptr(unsafe.Pointer(p16)), imageIcon,
		16, 16, lrLoadFromFile); hSmall != 0 {
		sendMessage.Call(hwnd, wmSetIcon, iconSmall, hSmall)
	}
}

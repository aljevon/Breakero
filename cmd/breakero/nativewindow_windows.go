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

	hwnd := uintptr(w.Window())
	setWindowIcon(hwnd)
	setDarkTitleBar(hwnd)
	w.Navigate(url)
	w.Run() // blocks until the window is closed
	return true
}

// setDarkTitleBar gives the window a dark title bar that matches the app,
// instead of the default white one, so it reads as a real dark-mode app. On
// Windows 11 it also tints the caption and text to the app's own colours. Any
// call that the running Windows build does not support returns an error that we
// simply ignore.
func setDarkTitleBar(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	dwm := syscall.NewLazyDLL("dwmapi.dll")
	set := dwm.NewProc("DwmSetWindowAttribute")

	const (
		dwmDarkMode20 = 20 // DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 2004+)
		dwmDarkMode19 = 19 // same attribute on Windows 10 1809/1903/1909
		dwmCaption    = 35 // DWMWA_CAPTION_COLOR (Windows 11)
		dwmText       = 36 // DWMWA_TEXT_COLOR   (Windows 11)
	)
	enabled := int32(1)
	if r, _, _ := set.Call(hwnd, dwmDarkMode20, uintptr(unsafe.Pointer(&enabled)), 4); r != 0 {
		set.Call(hwnd, dwmDarkMode19, uintptr(unsafe.Pointer(&enabled)), 4)
	}
	// COLORREF is 0x00BBGGRR. App background #0b0b0c, text #e8e8ea.
	caption := uint32(0x000C0B0B)
	set.Call(hwnd, dwmCaption, uintptr(unsafe.Pointer(&caption)), 4)
	text := uint32(0x00EAE8E8)
	set.Call(hwnd, dwmText, uintptr(unsafe.Pointer(&text)), 4)
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

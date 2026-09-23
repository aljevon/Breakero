//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// interactiveTerminal reports whether Breakero was started from a real terminal
// (cmd, PowerShell, Windows Terminal) as opposed to a double-click in Explorer.
// When you double-click, this process is the only one attached to the fresh
// console, so the process-list length is 1.
func interactiveTerminal() bool {
	dll := syscall.NewLazyDLL("kernel32.dll")
	proc := dll.NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return true
	}
	var pids [4]uint32
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return r > 1
}

// hideConsoleWindow hides the console window that Windows allocates when the exe
// is double-clicked, so the app shows only its browser UI and not a black box.
func hideConsoleWindow() {
	k := syscall.NewLazyDLL("kernel32.dll")
	u := syscall.NewLazyDLL("user32.dll")
	getConsole := k.NewProc("GetConsoleWindow")
	showWindow := u.NewProc("ShowWindow")
	hwnd, _, _ := getConsole.Call()
	if hwnd != 0 {
		const swHide = 0
		showWindow.Call(hwnd, uintptr(swHide))
	}
}

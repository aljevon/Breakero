//go:build !windows

package main

import "os"

// interactiveTerminal reports whether stdin is a real terminal. When the binary
// is launched from a file manager (double-click) there is no controlling tty,
// so this is false and Breakero opens its app UI instead of the CLI.
func interactiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// hideConsoleWindow is a no-op outside Windows.
func hideConsoleWindow() {}

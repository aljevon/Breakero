//go:build !windows

package main

// On macOS and Linux the self-install flow is optional. install.sh is the main
// way people set Breakero up, but -install here does the same basic thing:
// copy the binary into ~/.local/bin and tell you if that folder isn't on your
// PATH yet.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// platformStartup does nothing on Unix. Nothing auto-installs; you run the
// binary or use install.sh.
func platformStartup(set map[string]bool) (int, bool) { return 0, false }

func unixInstallDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "bin")
	}
	return "/usr/local/bin"
}

func onPath(dir string) bool {
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p == dir {
			return true
		}
	}
	return false
}

func doInstall() int {
	src, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
		return 1
	}
	data, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
		return 1
	}
	dir := unixInstallDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
		return 1
	}
	dst := filepath.Join(dir, "breakero")
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
		return 1
	}
	fmt.Println("Installed to " + dst)
	if !onPath(dir) {
		fmt.Println("That folder isn't on your PATH yet. Add this to your shell profile:")
		fmt.Println("    export PATH=\"" + dir + ":$PATH\"")
	}
	fmt.Println("Then run: breakero -explain")
	return 0
}

func doUninstall() int {
	dst := filepath.Join(unixInstallDir(), "breakero")
	if err := os.Remove(dst); err != nil {
		fmt.Fprintf(os.Stderr, "nothing to remove at %s\n", dst)
		return 1
	}
	fmt.Println("Removed " + dst)
	return 0
}

//go:build windows

package main

// Windows self-install. Breakero ships as a single exe, and on Windows that
// same exe knows how to set itself up. The first time you run it (typically by
// double-clicking), it copies itself into your local app data folder and adds
// that folder to your PATH, so afterwards you can just type "breakero" in any
// terminal. Run it again and it sees it's already installed and gets on with
// the job. Nothing here needs admin rights: everything lives under your own
// user profile.

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func installDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.Getenv("USERPROFILE")
	}
	return filepath.Join(base, "Breakero")
}

func installExe() string { return filepath.Join(installDir(), "breakero.exe") }

func isInstalled() bool {
	_, err := os.Stat(installExe())
	return err == nil
}

func runningFromInstall() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	abs, _ := filepath.Abs(exe)
	return strings.EqualFold(filepath.Clean(abs), filepath.Clean(installExe()))
}

func copyExe(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

// ensurePath adds dir to the user's PATH if it isn't already there. It uses
// PowerShell so it doesn't hit the length limits that setx runs into.
func ensurePath(dir string) {
	ps := fmt.Sprintf(`$d=%q; $p=[Environment]::GetEnvironmentVariable('Path','User'); if(-not $p){$p=''}; if($p -notlike ('*'+$d+'*')){[Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';')+';'+$d), 'User')}`, dir)
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
}

func removePath(dir string) {
	ps := fmt.Sprintf(`$d=%q; $p=[Environment]::GetEnvironmentVariable('Path','User'); if($p){$parts=$p.Split(';') | Where-Object { $_ -and ($_ -ne $d) }; [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')}`, dir)
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
}

func installSelf() (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", err
	}
	dst := installExe()
	if !strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		if err := copyExe(src, dst); err != nil {
			return "", err
		}
	}
	ensurePath(installDir())
	return dst, nil
}

// consoleWasDoubleClicked reports whether this process owns its console alone,
// which is what happens when you launch the exe from Explorer. If it was
// started from an existing terminal, the shell shares the console and the count
// is higher.
func consoleWasDoubleClicked() bool {
	dll := syscall.NewLazyDLL("kernel32.dll")
	proc := dll.NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return false
	}
	var pids [4]uint32
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return r <= 1
}

func pause() {
	fmt.Print("\n  Press Enter to close...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func showWelcome(justInstalled bool) {
	fmt.Println()
	fmt.Println("  Breakero " + version + "  |  Broken Access Control Scanner (OWASP A01:2025)")
	fmt.Println("  ============================================================")
	if justInstalled {
		fmt.Println("  Set up complete.")
		fmt.Println("  Copied to : " + installExe())
		fmt.Println("  PATH      : added, so a NEW terminal will find 'breakero'")
	} else {
		fmt.Println("  Already installed at " + installExe())
	}
	fmt.Println()
	fmt.Println("  It's a command-line tool. Open a terminal and try:")
	fmt.Println("    breakero -explain")
	fmt.Println("    breakero -url https://TARGET -i-am-authorized -html report.html")
	fmt.Println("    breakero -h")
	fmt.Println()
	fmt.Println("  Only test what you're allowed to test. See AUTHORIZATION.md.")
}

// platformStartup runs the Windows first-run flow. If the exe isn't installed
// yet it installs itself. If it was just double-clicked with no arguments, it
// shows a short welcome and waits, so the window doesn't flash and disappear.
// It returns (exitCode, true) when it has fully handled this run.
func platformStartup(set map[string]bool) (int, bool) {
	interactive := consoleWasDoubleClicked() && len(set) == 0 && len(flag.Args()) == 0

	justInstalled := false
	if !isInstalled() && !runningFromInstall() {
		if _, err := installSelf(); err == nil {
			justInstalled = true
		}
	}

	if interactive {
		showWelcome(justInstalled)
		pause()
		return 0, true
	}
	if justInstalled {
		fmt.Println("  (installed Breakero to " + installDir() + " and added it to PATH for new terminals)")
	}
	return 0, false
}

func doInstall() int {
	dst, err := installSelf()
	if err != nil {
		fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
		return 1
	}
	fmt.Println("Installed to " + dst)
	fmt.Println("Open a new terminal and run: breakero -explain")
	return 0
}

func doUninstall() int {
	removePath(installDir())
	if err := os.Remove(installExe()); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "could not remove %s: %v\n", installExe(), err)
	}
	_ = os.Remove(installDir()) // only succeeds if now empty
	fmt.Println("Removed Breakero from " + installDir() + " and from your PATH.")
	return 0
}

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aljevon/breakero/internal/webui"
)

// launchGUI starts the local app server, then shows the UI. It prefers a true
// native desktop window (Windows WebView2). If that isn't available it opens a
// dedicated app-mode browser window, and if no Chromium browser is found it
// falls back to the default browser. On Windows the console window is hidden so
// only the app shows.
func launchGUI() int {
	hideConsoleWindow()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := webui.New(version)
	url, wait, err := srv.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not start the Breakero app: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "  Breakero app running at "+url)
	fmt.Fprintln(os.Stderr, "  Close the window (or press Ctrl+C) to stop it.")

	// A real native window blocks until it is closed; then we stop the server.
	if runNativeWindow(url) {
		srv.Stop()
		return 0
	}

	// No native window: open a dedicated app-mode window and wait for the
	// server to stop (window closed, or Ctrl+C).
	go webui.OpenApp(url)
	wait()
	return 0
}

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aljevon/breakero/internal/webui"
)

// launchGUI starts the local app: it spins up a small web server bound to
// localhost, opens the default browser at it, and runs until the user closes
// the tab or quits. On Windows it first hides the console window so only the
// browser UI shows.
func launchGUI() int {
	hideConsoleWindow()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := webui.New(version)
	if _, err := srv.Run(ctx, true); err != nil {
		fmt.Fprintf(os.Stderr, "could not start the Breakero app: %v\n", err)
		return 1
	}
	return 0
}

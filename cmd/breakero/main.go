// Command breakero is a Broken Access Control tester for the OWASP Top 10 2025
// category A01. It is built for AUTHORIZED security testing and learning.
//
// Safety model (enforced, not advisory):
//   - It refuses to run unless you confirm authorization (--i-am-authorized or
//     authorized=true in the config file).
//   - It refuses to send any request to a host that is not explicitly in scope.
//   - It paces requests (rate limit) and honors a global request budget, so it
//     behaves like a tester, not a stress/denial-of-service tool.
//   - Data-changing HTTP methods are off unless you opt in with --active.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aljevon/breakero/internal/checks"
	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/engine"
	"github.com/aljevon/breakero/internal/httpx"
	"github.com/aljevon/breakero/internal/report"
	"github.com/aljevon/breakero/internal/scope"
)

const version = "1.9.0"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		fURL        = flag.String("url", "", "Target base URL, e.g. https://app.example.com (required unless -config sets base_url)")
		fConfig     = flag.String("config", "", "Path to a JSON config file (for multi-role / endpoint-aware scans)")
		fScope      = flag.String("scope", "", "Comma-separated extra in-scope hosts (supports *.example.com)")
		fExclude    = flag.String("exclude", "", "Comma-separated hosts to always exclude from scope")
		fCookie     = flag.String("cookie", "", "Cookie header for a quick authenticated scan (creates a 'user' role)")
		fHeaders    = flag.String("header", "", "Extra request header(s) for the 'user' role, 'Name: Value' (repeat with ';;')")
		fChecks     = flag.String("checks", "", "Comma-separated module ids to run (default: all). See -list-checks")
		fRate       = flag.Float64("rate", 5, "Max requests per second (kept modest to avoid stressing the target)")
		fMax        = flag.Int("max-requests", 2000, "Global request budget; the scan stops when it is reached")
		fTimeout    = flag.Int("timeout", 15, "Per-request timeout in seconds")
		fInsecure   = flag.Bool("insecure", false, "Accept self-signed TLS certs (for labs/staging only)")
		fRedirects  = flag.Bool("follow-redirects", false, "Follow redirects (stays within scope)")
		fActive     = flag.Bool("active", false, "Allow state-changing methods (POST/PUT/PATCH/DELETE). Use with care and permission")
		fJSON       = flag.String("json", "", "Write a JSON report to this path")
		fHTML       = flag.String("html", "", "Write a self-contained HTML report to this path")
		fAuthorized = flag.Bool("i-am-authorized", false, "Confirm you have written permission to test the target")
		fUA         = flag.String("user-agent", "", "Override the User-Agent header")
		fNoColor    = flag.Bool("no-color", false, "Disable colored terminal output")
		fQuiet      = flag.Bool("quiet", false, "Reduce progress logging")
		fList       = flag.Bool("list-checks", false, "List available check modules and exit")
		fExplain    = flag.Bool("explain", false, "Explain what each module does (great for learning) and exit")
		fVersion    = flag.Bool("version", false, "Print version and exit")
		fGui        = flag.Bool("gui", false, "Open the Breakero app (graphical UI in your browser)")
	)
	flag.Usage = usage
	flag.Parse()

	if *fVersion {
		fmt.Printf("Breakero %s\n", version)
		return 0
	}
	if *fList {
		listChecks()
		return 0
	}
	if *fExplain {
		explainChecks()
		return 0
	}

	// Track which flags the user explicitly set, so we only override config
	// values that were actually provided on the command line.
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// Open the graphical app when asked for it, or when the exe was launched
	// with no arguments outside a terminal (a double-click). Everything else
	// runs as the command-line tool.
	if *fGui || (len(set) == 0 && len(flag.Args()) == 0 && !interactiveTerminal()) {
		return launchGUI()
	}

	// Load config from file, or start from an empty one.
	var cfg *config.Config
	if *fConfig != "" {
		c, err := config.Load(*fConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		cfg = c
	} else {
		cfg = &config.Config{}
	}

	applyFlags(cfg, set, flagValues{
		url: *fURL, scope: *fScope, exclude: *fExclude, cookie: *fCookie,
		headers: *fHeaders, checks: *fChecks, rate: *fRate, max: *fMax,
		timeout: *fTimeout, insecure: *fInsecure, redirects: *fRedirects,
		active: *fActive, json: *fJSON, html: *fHTML, authorized: *fAuthorized,
		userAgent: *fUA,
	})

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "\nBreakero refused to start:\n  %v\n\n", err)
		fmt.Fprintln(os.Stderr, "Run 'breakero -h' for usage, or '-explain' to learn what it does.")
		return 2
	}

	printBanner(cfg, *fNoColor)

	// Build the shared, safety-wrapped HTTP client.
	sc := scope.New(cfg.ScopeHosts(), cfg.ScopeExclude)
	client := httpx.New(httpx.Options{
		Scope:           sc,
		RatePerSecond:   cfg.RatePerSecond,
		Timeout:         cfg.Timeout(),
		MaxRequests:     cfg.MaxRequests,
		FollowRedirects: cfg.FollowRedirects,
		InsecureTLS:     cfg.InsecureTLS,
		UserAgent:       cfg.UserAgent,
	})

	// Logger for progress; silenced in quiet mode.
	var logOut io.Writer = os.Stderr
	if *fQuiet {
		logOut = io.Discard
	}
	logger := log.New(logOut, "  · ", 0)

	selected := checks.Selected(cfg.Checks)
	if len(selected) == 0 {
		fmt.Fprintf(os.Stderr, "error: no valid check modules selected (see -list-checks)\n")
		return 2
	}

	// Graceful cancellation on Ctrl+C.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := engine.NewRunner(cfg, client, selected, logger)
	res, err := runner.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error during run: %v\n", err)
		return 1
	}

	report.Console(res, !*fNoColor)

	if cfg.JSONReport != "" {
		if err := report.WriteJSON(res, cfg.JSONReport, version); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write JSON report: %v\n", err)
		} else {
			fmt.Printf("  JSON report written to %s\n", cfg.JSONReport)
		}
	}
	if cfg.HTMLReport != "" {
		if err := report.WriteHTML(res, cfg.HTMLReport, version); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write HTML report: %v\n", err)
		} else {
			fmt.Printf("  HTML report written to %s\n", cfg.HTMLReport)
		}
	}
	return 0
}

type flagValues struct {
	url, scope, exclude, cookie, headers, checks string
	rate                                         float64
	max, timeout                                 int
	insecure, redirects, active, authorized      bool
	json, html, userAgent                        string
}

func applyFlags(cfg *config.Config, set map[string]bool, v flagValues) {
	if set["url"] {
		cfg.BaseURL = v.url
	}
	if set["scope"] {
		cfg.ScopeInclude = append(cfg.ScopeInclude, splitCSV(v.scope)...)
	}
	if set["exclude"] {
		cfg.ScopeExclude = append(cfg.ScopeExclude, splitCSV(v.exclude)...)
	}
	if set["checks"] {
		cfg.Checks = splitCSV(v.checks)
	}
	if set["rate"] {
		cfg.RatePerSecond = v.rate
	}
	if set["max-requests"] {
		cfg.MaxRequests = v.max
	}
	if set["timeout"] {
		cfg.TimeoutSeconds = v.timeout
	}
	if set["insecure"] {
		cfg.InsecureTLS = v.insecure
	}
	if set["follow-redirects"] {
		cfg.FollowRedirects = v.redirects
	}
	if set["active"] {
		cfg.AllowStateChanging = v.active
	}
	if set["json"] {
		cfg.JSONReport = v.json
	}
	if set["html"] {
		cfg.HTMLReport = v.html
	}
	if set["user-agent"] {
		cfg.UserAgent = v.userAgent
	}
	if set["i-am-authorized"] && v.authorized {
		cfg.Authorized = true
	}
	// Provide sensible defaults for a quick scan.
	if cfg.RatePerSecond == 0 {
		cfg.RatePerSecond = 5
	}
	if cfg.MaxRequests == 0 {
		cfg.MaxRequests = 2000
	}
	// A cookie/header on the command line defines a single authenticated
	// "user" role so the comparison-based checks have something to work with.
	if set["cookie"] || set["header"] {
		user := config.Role{Name: "user", Level: 10, Cookie: v.cookie}
		if v.headers != "" {
			user.Headers = parseHeaders(v.headers)
		}
		cfg.Roles = append(cfg.Roles, user)
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseHeaders(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ";;") {
		if i := strings.Index(pair, ":"); i >= 0 {
			k := strings.TrimSpace(pair[:i])
			val := strings.TrimSpace(pair[i+1:])
			if k != "" {
				out[k] = val
			}
		}
	}
	return out
}

func printBanner(cfg *config.Config, noColor bool) {
	b := func(s string) string {
		if noColor {
			return s
		}
		return "\033[1m" + s + "\033[0m"
	}
	fmt.Println()
	fmt.Println(b("  Breakero " + version + " — OWASP A01:2025 Broken Access Control tester"))
	fmt.Println("  Authorized testing only. You confirmed you have permission to test:")
	fmt.Printf("    target : %s\n", cfg.BaseURL)
	fmt.Printf("    scope  : %s\n", strings.Join(cfg.ScopeHosts(), ", "))
	fmt.Printf("    rate   : %.1f req/s, budget %d requests, state-changing methods: %v\n",
		cfg.RatePerSecond, cfg.MaxRequests, cfg.AllowStateChanging)
}

func listChecks() {
	fmt.Println("Available check modules (use with -checks id1,id2):")
	for _, c := range checks.All() {
		fmt.Printf("  %-16s %s\n", c.ID(), c.Title())
	}
}

func explainChecks() {
	fmt.Println("Breakero tests for OWASP Top 10 2025 — A01 Broken Access Control.")
	fmt.Println("Reference: https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/")
	fmt.Println()
	fmt.Println("Each module and what it looks for:")
	for _, c := range checks.All() {
		fmt.Printf("\n● %s (%s)\n", c.Title(), c.ID())
		for _, line := range wrap(c.Teaches(), 72) {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Println()
}

func wrap(s string, w int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if len(line)+len(word)+1 > w && line != "" {
			lines = append(lines, line)
			line = word
		} else if line == "" {
			line = word
		} else {
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func usage() {
	fmt.Fprintf(os.Stderr, `Breakero %s — OWASP A01:2025 Broken Access Control tester (authorized use only)

USAGE:
  breakero                       open the app (graphical UI in your browser)
  breakero -url https://target.example -i-am-authorized [options]
  breakero -config scan.json

QUICK START (beginner):
  breakero -gui                  point-and-click, no flags to remember
  breakero -url https://juice-shop.local -i-am-authorized -html report.html

COMMON OPTIONS:
  -url <url>              Target base URL (required unless -config sets base_url)
  -i-am-authorized        Confirm you have permission to test (required)
  -config <file>          JSON config for multi-role, endpoint-aware scans
  -cookie <cookie>        Cookie for a quick authenticated scan
  -checks <ids>           Only run these modules (see -list-checks)
  -rate <n>               Requests per second (default 5)
  -max-requests <n>       Global request budget (default 2000)
  -html <file>            Write a self-contained HTML report
  -json <file>            Write a JSON report
  -active                 Allow state-changing methods (POST/PUT/PATCH/DELETE)

LEARN:
  -list-checks            List the test modules
  -explain                Explain what each module does, in plain language

All options:
`, version)
	flag.PrintDefaults()
}

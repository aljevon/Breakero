// Package webui serves Breakero's graphical interface. The tool is a single
// binary; when you launch it as an app it starts a tiny local web server bound
// to 127.0.0.1, opens your browser at it, and serves a modern UI from there.
// That keeps the whole thing dependency-free and cross-platform while still
// giving a real, themed interface instead of a console.
//
// Safety is unchanged: a scan started from the UI goes through exactly the same
// engine, scope lock, rate limit and request budget as the command line, and it
// still requires the operator to confirm they are authorized.
package webui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aljevon/breakero/internal/checks"
	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/engine"
	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
	"github.com/aljevon/breakero/internal/report"
	"github.com/aljevon/breakero/internal/scope"
)

//go:embed assets/index.html
var assets embed.FS

// Server is the local web UI.
type Server struct {
	version string
	token   string

	mu   sync.Mutex
	last *engine.Result

	pings    chan struct{}
	shutdown context.CancelFunc
}

// New creates a Server with a fresh random access token. The token is placed in
// the URL that the browser opens and required on every API call, so a random
// web page cannot drive the scanner running on the user's machine.
func New(version string) *Server {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return &Server{
		version: version,
		token:   hex.EncodeToString(b),
		pings:   make(chan struct{}, 8),
	}
}

// Run starts the server, optionally opens the browser, and blocks until the
// context is cancelled, the browser tab goes away, or the user quits.
func (s *Server) Run(ctx context.Context, open bool) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	openURL := fmt.Sprintf("http://%s/?t=%s", addr, s.token)

	ctx, cancel := context.WithCancel(ctx)
	s.shutdown = cancel

	srv := &http.Server{Handler: s.handler()}
	go func() {
		<-ctx.Done()
		shutCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = srv.Shutdown(shutCtx)
	}()

	// Watchdog: if the browser tab stops sending keepalive pings (it was
	// closed), shut the app down so the process does not linger.
	go s.watchdog(ctx, cancel)

	fmt.Fprintln(os.Stderr, "  Breakero app running at "+openURL)
	fmt.Fprintln(os.Stderr, "  Close the browser tab (or press Ctrl+C) to stop it.")
	if open {
		go openBrowser(openURL)
	}

	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return openURL, nil
	}
	return openURL, err
}

// URL that the app is reachable at is only known after Run starts, so callers
// that need it (to print a hint) get it from Run's return value.

func (s *Server) watchdog(ctx context.Context, cancel context.CancelFunc) {
	// Generous first window so a slow browser start does not kill the app.
	t := time.NewTimer(45 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.pings:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(20 * time.Second)
		case <-t.C:
			cancel()
			return
		}
	}
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/checks", s.guard(s.handleChecks))
	mux.HandleFunc("/api/scan", s.guard(s.handleScan))
	mux.HandleFunc("/api/report.html", s.guard(s.handleReportHTML))
	mux.HandleFunc("/api/report.json", s.guard(s.handleReportJSON))
	mux.HandleFunc("/api/ping", s.guard(s.handlePing))
	mux.HandleFunc("/api/quit", s.guard(s.handleQuit))
	return mux
}

// guard rejects requests without the right token or from a non-local host, so
// only the page we opened can talk to the scanner.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localHost(r.Host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		tok := r.Header.Get("X-Breakero-Token")
		if tok == "" {
			tok = r.URL.Query().Get("t")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func localHost(host string) bool {
	h := host
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	h = strings.Trim(h, "[]")
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "ui not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

type checkInfo struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Teaches string `json:"teaches"`
}

func (s *Server) handleChecks(w http.ResponseWriter, r *http.Request) {
	var out []checkInfo
	for _, c := range checks.All() {
		out = append(out, checkInfo{ID: c.ID(), Title: c.Title(), Teaches: c.Teaches()})
	}
	writeJSON(w, map[string]any{"version": s.version, "checks": out})
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	select {
	case s.pings <- struct{}{}:
	default:
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleQuit(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
	if s.shutdown != nil {
		go func() {
			time.Sleep(150 * time.Millisecond)
			s.shutdown()
		}()
	}
}

type scanRequest struct {
	URL         string   `json:"url"`
	Authorized  bool     `json:"authorized"`
	Rate        float64  `json:"rate"`
	MaxRequests int      `json:"max_requests"`
	Active      bool     `json:"active"`
	Cookie      string   `json:"cookie"`
	Checks      []string `json:"checks"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	cfg := &config.Config{
		Authorized:         req.Authorized,
		BaseURL:            strings.TrimSpace(req.URL),
		RatePerSecond:      req.Rate,
		MaxRequests:        req.MaxRequests,
		AllowStateChanging: req.Active,
		Checks:             req.Checks,
	}
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = 12
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 1500
	}
	if strings.TrimSpace(req.Cookie) != "" {
		cfg.Roles = append(cfg.Roles, config.Role{Name: "user", Level: 10, Cookie: req.Cookie})
	}

	// NDJSON stream: one JSON object per line, flushed as it happens.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	emit := func(v any) {
		_ = enc.Encode(v)
		if flusher != nil {
			flusher.Flush()
		}
	}

	if err := cfg.Validate(); err != nil {
		emit(map[string]any{"type": "error", "message": err.Error()})
		return
	}

	sc := scope.New(cfg.ScopeHosts(), cfg.ScopeExclude)
	client := httpx.New(httpx.Options{
		Scope:         sc,
		RatePerSecond: cfg.RatePerSecond,
		Timeout:       cfg.Timeout(),
		MaxRequests:   cfg.MaxRequests,
	})
	selected := checks.Selected(cfg.Checks)
	if len(selected) == 0 {
		emit(map[string]any{"type": "error", "message": "no valid checks selected"})
		return
	}
	logger := log.New(io.Discard, "", 0)
	runner := engine.NewRunner(cfg, client, selected, logger)
	runner.OnStart = func(total int, catchAll bool) {
		emit(map[string]any{"type": "start", "total": total, "catchAll": catchAll,
			"scope": cfg.ScopeHosts()})
	}
	runner.OnCheck = func(run engine.CheckRun, found []finding.Finding) {
		emit(map[string]any{"type": "check", "id": run.ID, "title": run.Title,
			"count": run.Findings, "err": run.Err})
		for _, f := range found {
			emit(map[string]any{"type": "finding", "finding": f})
		}
	}

	res, err := runner.Run(r.Context())
	if err != nil {
		emit(map[string]any{"type": "error", "message": err.Error()})
		return
	}

	s.mu.Lock()
	s.last = res
	s.mu.Unlock()

	summary := map[string]int{}
	for sev, n := range finding.Counts(res.Findings) {
		summary[strings.ToLower(sev.String())] = n
	}
	emit(map[string]any{
		"type":       "done",
		"summary":    summary,
		"total":      len(res.Findings),
		"requests":   res.Requests,
		"durationMs": res.Duration().Milliseconds(),
	})
}

func (s *Server) handleReportHTML(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	res := s.last
	s.mu.Unlock()
	if res == nil {
		http.Error(w, "no scan yet", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="breakero-report.html"`)
	_, _ = w.Write(report.RenderHTML(res, s.version))
}

func (s *Server) handleReportJSON(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	res := s.last
	s.mu.Unlock()
	if res == nil {
		http.Error(w, "no scan yet", http.StatusNotFound)
		return
	}
	data, err := report.RenderJSON(res, s.version)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="breakero-report.json"`)
	_, _ = w.Write(data)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// openBrowser opens the default browser at url on any desktop OS.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

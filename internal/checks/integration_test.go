package checks_test

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aljevon/breakero/internal/checks"
	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/engine"
	"github.com/aljevon/breakero/internal/httpx"
	"github.com/aljevon/breakero/internal/scope"
)

// vulnerableServer is a deliberately insecure app used only to prove Breakero's
// detection logic. It reproduces several Broken Access Control patterns.
func vulnerableServer() *httptest.Server {
	mux := http.NewServeMux()

	// Missing authentication: admin content served to anyone.
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "<h1>Admin Dashboard</h1> secret controls: delete users, edit config")
	})

	// IDOR: object endpoint with no ownership check; content varies by id.
	mux.HandleFunc("/api/item", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
		io.WriteString(w, "item id="+id+" owner-data for record "+id+" lorem ipsum dolor sit amet")
	})

	// Header-based bypass: 403 unless a trusted-looking header is present.
	mux.HandleFunc("/internal", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.WriteHeader(200)
			io.WriteString(w, "internal metrics: cpu, memory, secrets")
			return
		}
		w.WriteHeader(403)
		io.WriteString(w, "forbidden")
	})

	// CORS misconfiguration: reflects Origin and allows credentials.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
		io.WriteString(w, "welcome home page content here for everyone to see normally")
	})

	return httptest.NewServer(mux)
}

func newTestRunner(t *testing.T, srv *httptest.Server, cfg *config.Config, ids ...string) *engine.Runner {
	t.Helper()
	sc := scope.New(cfg.ScopeHosts(), nil)
	client := httpx.New(httpx.Options{
		Scope:         sc,
		RatePerSecond: 1000, // fast for tests
		Timeout:       5 * time.Second,
		MaxRequests:   500,
	})
	selected := checks.Selected(ids)
	logger := log.New(io.Discard, "", 0)
	return engine.NewRunner(cfg, client, selected, logger)
}

func TestDetectsMissingAuthAndForcedBrowse(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()

	cfg := &config.Config{
		Authorized: true,
		BaseURL:    srv.URL,
		Endpoints: []config.Endpoint{
			{Path: "/admin", Method: "GET", Sensitive: true},
		},
	}
	runner := newTestRunner(t, srv, cfg, "unauth", "forced-browse")
	res, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings for /admin served without auth, got none")
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.URL, "/admin") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a finding referencing /admin, got: %+v", res.Findings)
	}
}

func TestDetectsIDOR(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()

	cfg := &config.Config{
		Authorized: true,
		BaseURL:    srv.URL,
		Roles: []config.Role{
			{Name: "alice", Level: 10, OwnedIDs: []string{"1001"}},
			{Name: "bob", Level: 10, OwnedIDs: []string{"1002"}},
		},
		Endpoints: []config.Endpoint{
			{Path: "/api/item", Method: "GET", IDParam: "id"},
		},
	}
	runner := newTestRunner(t, srv, cfg, "idor")
	res, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected IDOR findings, got none")
	}
	// At least one cross-user access finding should be present and confident,
	// because the response echoes the other user's id.
	sawConfident := false
	for _, f := range res.Findings {
		if f.Check == "idor" && f.Confidence == "likely" {
			sawConfident = true
		}
	}
	if !sawConfident {
		t.Fatalf("expected a confident cross-user IDOR finding, got: %+v", res.Findings)
	}
}

func TestDetectsHeaderBypass(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()

	cfg := &config.Config{
		Authorized: true,
		BaseURL:    srv.URL,
		Endpoints: []config.Endpoint{
			{Path: "/internal", Method: "GET", Sensitive: true},
		},
	}
	runner := newTestRunner(t, srv, cfg, "header-bypass")
	res, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Check == "header-bypass" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a header-bypass finding for /internal, got: %+v", res.Findings)
	}
}

func TestDetectsCORS(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()

	cfg := &config.Config{
		Authorized: true,
		BaseURL:    srv.URL,
	}
	runner := newTestRunner(t, srv, cfg, "cors")
	res, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Check == "cors" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a CORS finding, got: %+v", res.Findings)
	}
}

func TestScopeBlocksOutOfScopeHost(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()

	// Configure a scope that does NOT include the server host; every request
	// must be refused, so no findings can be produced.
	cfg := &config.Config{
		Authorized:   true,
		BaseURL:      srv.URL,
		ScopeInclude: []string{"only-this-host.example"},
	}
	runner := newTestRunner(t, srv, cfg, "unauth", "forced-browse", "cors")
	res, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("scope should have blocked all requests, but got findings: %+v", res.Findings)
	}
	if res.Requests != 0 {
		t.Fatalf("expected 0 requests sent when target is out of scope, got %d", res.Requests)
	}
}

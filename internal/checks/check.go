// Package checks contains the individual Broken Access Control test modules.
//
// Each module implements Check. A module is intentionally small and focused on
// one class of A01:2025 weakness so that its output is easy to understand and
// easy to trust. Every module must go through the shared httpx.Client, which
// enforces scope, rate limiting, and the request budget.
package checks

import (
	"context"
	"log"

	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// Context carries everything a check needs to run.
type Context struct {
	Ctx    context.Context
	Client *httpx.Client
	Config *config.Config
	Log    *log.Logger

	// NotFound is the response the server gave for a deliberately random,
	// non-existent path. When CatchAll is true, the server returns "success"
	// content for paths that do not exist (a soft 404 / catch-all handler).
	// Checks use this to avoid reporting every guessed path as a finding.
	NotFound *httpx.Response
	CatchAll bool
}

// LooksLikeCatchAll reports whether a granted response is really just the
// server's catch-all/soft-404 page rather than a distinct, exposed resource.
// It returns false when no catch-all baseline was established.
func (c *Context) LooksLikeCatchAll(resp *httpx.Response) bool {
	if !c.CatchAll || c.NotFound == nil || resp == nil {
		return false
	}
	return similarity(resp.Body, c.NotFound.Body) > 0.9
}

// Check is one Broken Access Control test module.
type Check interface {
	// ID is the short, stable identifier (e.g. "idor").
	ID() string
	// Title is a human-readable name.
	Title() string
	// Teaches returns a short, beginner-friendly explanation of what this
	// module looks for and why it matters. Shown in --explain and reports.
	Teaches() string
	// Run executes the module and returns any findings.
	Run(c *Context) ([]finding.Finding, error)
}

// All returns every available check module in a sensible default order.
func All() []Check {
	return []Check{
		&UnauthCheck{},
		&ForcedBrowseCheck{},
		&PrivEscCheck{},
		&IDORCheck{},
		&MethodCheck{},
		&HeaderBypassCheck{},
		&CORSCheck{},
		&TraversalCheck{},
		&JWTCheck{},
	}
}

// Selected returns the checks whose IDs appear in names. An empty or nil names
// slice returns all checks. Unknown names are ignored by the caller.
func Selected(names []string) []Check {
	if len(names) == 0 {
		return All()
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []Check
	for _, c := range All() {
		if want[c.ID()] {
			out = append(out, c)
		}
	}
	return out
}

// KnownIDs lists every module id, for help text and validation.
func KnownIDs() []string {
	var ids []string
	for _, c := range All() {
		ids = append(ids, c.ID())
	}
	return ids
}

// defaultSensitivePaths is a small, conservative wordlist of paths that are
// commonly protected. Forced browsing tries to reach them without credentials.
// The list is deliberately short so a default scan stays fast and low-noise.
var defaultSensitivePaths = []string{
	"/admin",
	"/admin/",
	"/admin/login",
	"/admin/dashboard",
	"/administrator",
	"/dashboard",
	"/manage",
	"/management",
	"/config",
	"/settings",
	"/api/admin",
	"/api/users",
	"/api/v1/users",
	"/api/internal",
	"/user/1",
	"/users",
	"/account",
	"/actuator",
	"/actuator/env",
	"/metrics",
	"/debug",
	"/.git/config",
	"/server-status",
	"/phpinfo.php",
	"/wp-admin/",
}

// endpointsOrDefault returns configured endpoints, or a minimal default set
// derived from the sensitive-path wordlist when none are configured.
func endpointsOrDefault(cfg *config.Config) []config.Endpoint {
	if len(cfg.Endpoints) > 0 {
		return cfg.Endpoints
	}
	eps := make([]config.Endpoint, 0, len(defaultSensitivePaths))
	for _, p := range defaultSensitivePaths {
		eps = append(eps, config.Endpoint{Path: p, Method: "GET", Sensitive: true})
	}
	return eps
}

// methodOf returns the endpoint method, defaulting to GET.
func methodOf(e config.Endpoint) string {
	if e.Method == "" {
		return "GET"
	}
	return e.Method
}

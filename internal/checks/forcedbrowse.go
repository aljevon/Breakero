package checks

import (
	"fmt"
	"strings"

	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// ForcedBrowseCheck tries to reach commonly-protected paths (admin panels,
// dashboards, management endpoints, exposed config) directly by URL, without
// any credentials. OWASP calls this "force browsing": guessing the address of
// a privileged page instead of clicking a link to it.
//
// It only requests paths from a short, conservative built-in wordlist (or the
// configured endpoints), so a default scan stays fast and quiet.
type ForcedBrowseCheck struct{}

func (ForcedBrowseCheck) ID() string    { return "forced-browse" }
func (ForcedBrowseCheck) Title() string { return "Force browsing to sensitive paths" }
func (ForcedBrowseCheck) Teaches() string {
	return "Admin panels and config pages are often 'hidden' only because there is " +
		"no link to them. This test types their likely addresses directly. If one " +
		"opens without a login, attackers can find it the same way."
}

func (c *ForcedBrowseCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()

	// Use the built-in wordlist unless the user configured explicit endpoints,
	// in which case honor their list.
	var paths []config.Endpoint
	if len(cfg.Endpoints) > 0 {
		paths = cfg.Endpoints
	} else {
		for _, p := range defaultSensitivePaths {
			paths = append(paths, config.Endpoint{Path: p, Method: "GET", Sensitive: true})
		}
	}

	var out []finding.Finding
	for _, ep := range paths {
		if ctx.Client.BudgetExceeded() {
			return out, nil
		}
		u, err := cfg.NormalizeURL(ep.Path)
		if err != nil {
			continue
		}
		resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
			Method: "GET", URL: u,
			Headers: anon.Headers, Cookie: anon.Cookie,
		})
		if err != nil {
			continue
		}
		if !isGrantedContent(resp) {
			continue
		}
		if ctx.LooksLikeCatchAll(resp) {
			continue // matches the server's catch-all/soft-404 page; not a real exposure
		}

		sev := finding.Medium
		if ep.Sensitive || looksAdminPath(ep.Path) {
			sev = finding.High
		}
		// Exposed source control / actuator / server-status are especially bad.
		if strings.Contains(ep.Path, ".git") || strings.Contains(ep.Path, "actuator") ||
			strings.Contains(ep.Path, "server-status") || strings.Contains(ep.Path, "phpinfo") {
			sev = finding.Critical
		}

		out = append(out, finding.New(c.ID(),
			"Sensitive path reachable without authentication: "+ep.Path, sev).
			WithURL(u).WithMethod("GET").
			WithMeaning(c.Teaches()).
			WithEvidence("Direct request without credentials succeeded: "+evidenceForResponse(resp)).
			WithConfidence("likely").
			WithRemediation(fmt.Sprintf(
				"Protect %q behind authentication and authorization, or remove it from the "+
					"public server entirely if it is not meant to be exposed. For framework "+
					"admin/actuator/debug endpoints, disable them in production or bind them to "+
					"an internal network only.", ep.Path)))
	}
	return out, nil
}

func looksAdminPath(p string) bool {
	p = strings.ToLower(p)
	for _, m := range []string{"admin", "manage", "internal", "config", "dashboard", "debug"} {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

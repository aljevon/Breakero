package checks

import (
	"fmt"
	"net/url"
	"regexp"
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
		// Pull extra paths the site itself reveals in robots.txt and sitemap.xml.
		// robots.txt in particular often lists the very admin URLs it wants to
		// hide from search engines, which is a gift for access-control testing.
		for _, p := range discoverPaths(ctx) {
			paths = append(paths, config.Endpoint{Path: p, Method: "GET", Sensitive: false})
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
			WithRepro(repro("GET", u, anon.Headers,
				"Paste the URL into a private/incognito window (logged out). If the page opens, "+
					"the path is reachable by anyone who guesses it.")).
			WithRemediation(fmt.Sprintf(
				"Protect %q behind authentication and authorization, or remove it from the "+
					"public server entirely if it is not meant to be exposed. For framework "+
					"admin/actuator/debug endpoints, disable them in production or bind them to "+
					"an internal network only.", ep.Path)))
	}
	return out, nil
}

var sitemapLoc = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)

// discoverPaths reads robots.txt and sitemap.xml and returns extra in-scope
// paths worth trying. It is capped so it cannot balloon a scan.
func discoverPaths(ctx *Context) []string {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()
	seen := map[string]bool{}
	for _, p := range defaultSensitivePaths {
		seen[p] = true
	}
	var found []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") || seen[p] || len(found) >= 40 {
			return
		}
		if strings.ContainsAny(p, " \t") || len(p) > 128 {
			return
		}
		seen[p] = true
		found = append(found, p)
	}

	get := func(path string) string {
		u, err := cfg.NormalizeURL(path)
		if err != nil {
			return ""
		}
		resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
			Method: "GET", URL: u, Headers: anon.Headers, Cookie: anon.Cookie,
		})
		if err != nil || resp.Status < 200 || resp.Status >= 300 {
			return ""
		}
		return resp.BodyString()
	}

	// robots.txt: Disallow/Allow lines carry paths.
	for _, line := range strings.Split(get("/robots.txt"), "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "disallow:") || strings.HasPrefix(low, "allow:") {
			val := strings.TrimSpace(line[strings.Index(line, ":")+1:])
			if i := strings.IndexAny(val, "*?#"); i >= 0 {
				val = val[:i]
			}
			add(val)
		}
	}

	// sitemap.xml: <loc> entries, kept to same-host paths.
	base, _ := url.Parse(cfg.BaseURL)
	for _, m := range sitemapLoc.FindAllStringSubmatch(get("/sitemap.xml"), -1) {
		if lu, err := url.Parse(strings.TrimSpace(m[1])); err == nil {
			if lu.Host == "" || (base != nil && lu.Host == base.Host) {
				add(lu.Path)
			}
		}
	}
	if len(found) > 0 {
		ctx.Log.Printf("[forced-browse] discovered %d extra paths from robots.txt/sitemap.xml", len(found))
	}
	return found
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

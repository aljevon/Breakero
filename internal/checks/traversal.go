package checks

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// TraversalCheck performs read-only detection of path traversal on endpoints
// that take a path-like parameter. Path traversal is an access-control failure:
// it lets a request reach files outside the directory the application intended
// to expose. OWASP groups it under A01.
//
// This check is detection-only. It requests a few classic traversal sequences
// and looks for tell-tale file signatures in the response. It never writes,
// deletes, or attempts to exfiltrate large files (bodies are capped by httpx).
type TraversalCheck struct{}

func (TraversalCheck) ID() string    { return "path-traversal" }
func (TraversalCheck) Title() string { return "Path traversal (accessing files outside scope)" }
func (TraversalCheck) Teaches() string {
	return "If a page loads a file based on a parameter (like ?file=report.pdf), an " +
		"attacker may try ?file=../../../../etc/passwd to escape the intended folder " +
		"and read system files. This test looks for that escape using a few classic " +
		"patterns, reading only enough to confirm the problem."
}

// traversalPayloads are classic sequences; kept small to stay fast and low-noise.
var traversalPayloads = []string{
	"../../../../../../etc/passwd",
	"..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
	"....//....//....//....//etc/passwd",
	"..\\..\\..\\..\\..\\..\\windows\\win.ini",
}

// signatures that indicate a traversal succeeded.
var traversalSignatures = []string{
	"root:x:0:0:",
	"root:!:0:0:",
	"[extensions]", // win.ini
	"[fonts]",      // win.ini
	"; for 16-bit app support",
}

func (c *TraversalCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()

	// Only endpoints that expose a file/path-like parameter are relevant.
	endpoints := traversalEndpoints(cfg)
	if len(endpoints) == 0 {
		ctx.Log.Printf("[path-traversal] skipped: no endpoints with a file/path parameter configured " +
			"(set id_param to the parameter name, e.g. \"file\")")
		return nil, nil
	}

	var out []finding.Finding
	for _, ep := range endpoints {
		for _, payload := range traversalPayloads {
			if ctx.Client.BudgetExceeded() {
				return out, nil
			}
			u, err := injectParam(cfg, ep, payload)
			if err != nil {
				continue
			}
			resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
				Method: "GET", URL: u, Headers: anon.Headers, Cookie: anon.Cookie,
			})
			if err != nil {
				continue
			}
			if sig := matchSignature(resp.BodyString()); sig != "" {
				out = append(out, finding.New(c.ID(),
					fmt.Sprintf("Path traversal confirmed on %s (parameter %q)", ep.Path, ep.IDParam),
					finding.Critical).
					WithURL(u).WithMethod("GET").
					WithMeaning(c.Teaches()).
					WithEvidence(fmt.Sprintf("Payload %q returned a response containing the signature %q, "+
						"indicating a system file was read.", payload, sig)).
					WithConfidence("confirmed").
					WithRemediation("Never build a filesystem path directly from user input. Resolve the "+
						"requested path and confirm it stays within an allowed base directory, reject any "+
						"input containing path separators or '..', and prefer an allow-list of known-good "+
						"file identifiers mapped server-side to real paths."))
				break // one confirmation per endpoint is enough
			}
		}
	}
	return out, nil
}

func traversalEndpoints(cfg *config.Config) []config.Endpoint {
	var eps []config.Endpoint
	for _, e := range cfg.Endpoints {
		name := strings.ToLower(e.IDParam)
		if name == "" {
			continue
		}
		if strings.Contains(name, "file") || strings.Contains(name, "path") ||
			strings.Contains(name, "doc") || strings.Contains(name, "page") ||
			strings.Contains(name, "template") || strings.Contains(name, "name") {
			eps = append(eps, e)
		}
	}
	return eps
}

func injectParam(cfg *config.Config, ep config.Endpoint, payload string) (string, error) {
	full, err := cfg.NormalizeURL(ep.Path)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(full)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(ep.IDParam, payload)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func matchSignature(body string) string {
	for _, sig := range traversalSignatures {
		if strings.Contains(body, sig) {
			return sig
		}
	}
	return ""
}

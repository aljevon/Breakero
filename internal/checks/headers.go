package checks

import (
	"fmt"

	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// HeaderBypassCheck tests whether an access-control decision can be flipped by
// adding a request header that a front-end proxy or the application trusts too
// much. These are well-known Broken Access Control bypasses: the edge denies
// /admin, but an internal rewrite header or a spoofed client IP re-opens it.
//
// All requests are read-only GETs. The check only acts on endpoints that are
// currently denied, then re-requests them with one extra header at a time.
type HeaderBypassCheck struct{}

func (HeaderBypassCheck) ID() string    { return "header-bypass" }
func (HeaderBypassCheck) Title() string { return "Access-control bypass via request headers" }
func (HeaderBypassCheck) Teaches() string {
	return "Websites sitting behind a proxy sometimes trust special headers such as " +
		"X-Forwarded-For or X-Original-URL. If the app believes 'the request came " +
		"from inside the building' just because a header says so, an outsider can add " +
		"that header and walk past the guard."
}

// bypassHeaders are single headers known to flip access decisions on
// misconfigured stacks. The value is chosen to assert privileged/internal origin.
var bypassHeaders = []struct {
	name  string
	value string
	note  string
}{
	{"X-Forwarded-For", "127.0.0.1", "spoofed trusted client IP"},
	{"X-Forwarded-Host", "localhost", "spoofed trusted host"},
	{"X-Originating-IP", "127.0.0.1", "spoofed originating IP"},
	{"X-Remote-IP", "127.0.0.1", "spoofed remote IP"},
	{"X-Remote-Addr", "127.0.0.1", "spoofed remote address"},
	{"X-Client-IP", "127.0.0.1", "spoofed client IP"},
	{"X-Host", "localhost", "spoofed host"},
	{"X-Custom-IP-Authorization", "127.0.0.1", "framework IP allow header"},
	{"X-Original-URL", "/", "proxy URL rewrite"},
	{"X-Rewrite-URL", "/", "proxy URL rewrite"},
}

func (c *HeaderBypassCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()

	var out []finding.Finding
	for _, ep := range endpointsOrDefault(cfg) {
		if ctx.Client.BudgetExceeded() {
			return out, nil
		}
		u, err := cfg.NormalizeURL(ep.Path)
		if err != nil {
			continue
		}
		base, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
			Method: "GET", URL: u, Headers: anon.Headers, Cookie: anon.Cookie,
		})
		if err != nil {
			continue
		}
		if base.Status != 401 && base.Status != 403 {
			continue // only interesting when the edge explicitly denies
		}

		for _, h := range bypassHeaders {
			if ctx.Client.BudgetExceeded() {
				return out, nil
			}
			headers := map[string]string{h.name: h.value}
			for k, v := range anon.Headers {
				headers[k] = v
			}
			resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
				Method: "GET", URL: u, Headers: headers, Cookie: anon.Cookie,
			})
			if err != nil {
				continue
			}
			if resp.Status >= 200 && resp.Status < 400 && !resp.LooksAuthenticatedGate() {
				out = append(out, finding.New(c.ID(),
					fmt.Sprintf("Denial bypassed with header %s: %s", h.name, ep.Path), finding.High).
					WithURL(u).WithMethod("GET").
					WithMeaning(c.Teaches()).
					WithEvidence(fmt.Sprintf("Plain request returned HTTP %d, but adding %q: %q (%s) "+
						"returned HTTP %d.", base.Status, h.name, h.value, h.note, resp.Status)).
					WithConfidence("likely").
					WithRemediation("Do not make authorization decisions from client-supplied headers. Strip "+
						"or normalize X-Forwarded-* and X-Original-URL/X-Rewrite-URL at the trusted edge, and "+
						"enforce the real access-control check in the application against the authenticated "+
						"identity, not a header value."))
			}
		}
	}
	return out, nil
}

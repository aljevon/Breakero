package checks

import (
	"fmt"
	"strings"

	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// CORSCheck looks for Cross-Origin Resource Sharing misconfigurations. CORS is
// an access-control mechanism: it decides which other websites are allowed to
// read responses from this one. A permissive policy lets an attacker's site
// read a victim's authenticated data, which OWASP lists under A01.
//
// It sends a crafted Origin header and inspects the reflected
// Access-Control-Allow-Origin / Access-Control-Allow-Credentials response.
type CORSCheck struct{}

func (CORSCheck) ID() string    { return "cors" }
func (CORSCheck) Title() string { return "CORS misconfiguration" }
func (CORSCheck) Teaches() string {
	return "CORS is the rule that decides which OTHER websites may read this site's " +
		"responses in a browser. If the server echoes back any origin AND allows " +
		"credentials, a malicious page you visit could quietly read your logged-in " +
		"data from the target. This test checks that rule with a fake origin."
}

func (c *CORSCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()

	// Probe the base URL and any configured endpoints.
	targets := map[string]bool{}
	if u, err := cfg.NormalizeURL("/"); err == nil {
		targets[u] = true
	}
	for _, ep := range cfg.Endpoints {
		if u, err := cfg.NormalizeURL(ep.Path); err == nil {
			targets[u] = true
		}
	}

	evilOrigin := "https://breakero-cors-test.example"
	var out []finding.Finding

	for u := range targets {
		if ctx.Client.BudgetExceeded() {
			return out, nil
		}
		before := len(out)
		for _, origin := range []string{evilOrigin, "null"} {
			resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
				Method: "GET", URL: u,
				Headers: mergeHeaders(anon.Headers, map[string]string{"Origin": origin}),
				Cookie:  anon.Cookie,
			})
			if err != nil {
				continue
			}
			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
			if acao == "" {
				continue
			}

			reflected := acao == origin
			wildcard := acao == "*"
			nullAllowed := origin == "null" && acao == "null"

			switch {
			case (reflected || nullAllowed) && acac:
				out = append(out, finding.New(c.ID(),
					"Dangerous CORS policy: reflects arbitrary origin with credentials", finding.High).
					WithURL(u).WithMethod("GET").
					WithMeaning(c.Teaches()).
					WithEvidence(fmt.Sprintf("Origin %q was reflected as Access-Control-Allow-Origin=%q "+
						"together with Access-Control-Allow-Credentials: true.", origin, acao)).
					WithConfidence("likely").
					WithRemediation("Never reflect the Origin header blindly. Maintain a strict allow-list of "+
						"trusted origins, and only send Access-Control-Allow-Credentials: true for those exact "+
						"origins. Never combine credentials with a wildcard or a reflected/null origin."))
			case reflected && !acac:
				out = append(out, finding.New(c.ID(),
					"Permissive CORS policy: reflects arbitrary origin", finding.Medium).
					WithURL(u).WithMethod("GET").
					WithMeaning(c.Teaches()).
					WithEvidence(fmt.Sprintf("Origin %q was reflected as Access-Control-Allow-Origin. "+
						"Credentials are not allowed, which limits (but does not remove) the risk.", origin)).
					WithConfidence("needs-review").
					WithRemediation("Reflect only origins from a vetted allow-list rather than echoing whatever "+
						"the client sends."))
			case wildcard && acac:
				out = append(out, finding.New(c.ID(),
					"Invalid CORS policy: wildcard origin with credentials", finding.Medium).
					WithURL(u).WithMethod("GET").
					WithMeaning(c.Teaches()).
					WithEvidence("Access-Control-Allow-Origin: * combined with Allow-Credentials: true "+
						"(browsers reject this combination, but it signals a misunderstanding of the policy).").
					WithConfidence("needs-review").
					WithRemediation("Do not use a wildcard origin when credentials are involved. Use an explicit "+
						"allow-list of origins."))
			}
			// One CORS finding per URL is enough; don't repeat it for each
			// probe origin.
			if len(out) > before {
				break
			}
		}
	}
	return out, nil
}

func mergeHeaders(base, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

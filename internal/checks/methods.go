package checks

import (
	"fmt"

	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// MethodCheck tests for HTTP method (verb) tampering. Access control is
// sometimes applied to GET but forgotten on other methods, or an unusual verb
// slips past a filter that only lists the common ones.
//
// By default it is non-destructive: it only sends safe, read-only methods
// (HEAD, OPTIONS) plus a made-up verb to probe filter behavior. State-changing
// verbs (POST, PUT, PATCH, DELETE) are only sent when the operator explicitly
// enables allow_state_changing, because those can modify or delete data.
type MethodCheck struct{}

func (MethodCheck) ID() string    { return "method-tampering" }
func (MethodCheck) Title() string { return "HTTP method / verb tampering" }
func (MethodCheck) Teaches() string {
	return "A server might block GET /admin but forget to block HEAD, OPTIONS, or an " +
		"odd verb like FOO on the same address. This test tries other HTTP methods " +
		"to see whether the access-control rule covers all of them. Dangerous verbs " +
		"that change data are only used if you explicitly turn them on."
}

func (c *MethodCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()

	safeVerbs := []string{"HEAD", "OPTIONS", "TRACE", "FOOBAR"}
	stateVerbs := []string{"POST", "PUT", "PATCH", "DELETE"}

	var out []finding.Finding
	for _, ep := range endpointsOrDefault(cfg) {
		if ctx.Client.BudgetExceeded() {
			return out, nil
		}
		u, err := cfg.NormalizeURL(ep.Path)
		if err != nil {
			continue
		}

		// Baseline: a normal GET as an anonymous user. We only care about
		// endpoints that are currently DENIED, because the point is finding a
		// verb that bypasses that denial.
		base, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
			Method: "GET", URL: u, Headers: anon.Headers, Cookie: anon.Cookie,
		})
		if err != nil {
			continue
		}
		if isGrantedContent(base) {
			continue // already open; the unauth check covers this
		}

		verbs := append([]string{}, safeVerbs...)
		if cfg.AllowStateChanging {
			verbs = append(verbs, stateVerbs...)
		}

		for _, verb := range verbs {
			if ctx.Client.BudgetExceeded() {
				return out, nil
			}
			resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
				Method: verb, URL: u, Headers: anon.Headers, Cookie: anon.Cookie,
			})
			if err != nil {
				continue
			}
			// Success on a verb where GET was denied indicates inconsistent
			// method-level access control.
			granted := resp.Status >= 200 && resp.Status < 400 && !resp.LooksAuthenticatedGate()
			if !granted {
				continue
			}
			sev := finding.Medium
			if verb == "PUT" || verb == "DELETE" || verb == "PATCH" || verb == "POST" {
				sev = finding.High
			}
			out = append(out, finding.New(c.ID(),
				fmt.Sprintf("Access control inconsistent across methods: %s %s allowed while GET is denied",
					verb, ep.Path), sev).
				WithURL(u).WithMethod(verb).
				WithMeaning(c.Teaches()).
				WithEvidence(fmt.Sprintf("GET returned HTTP %d (denied) but %s returned HTTP %d.",
					base.Status, verb, resp.Status)).
				WithConfidence("needs-review").
				WithRepro(repro(verb, u, anon.Headers,
					"Resend the request using the "+verb+" method (curl -X, or Burp Repeater). "+
						"If it succeeds while GET is blocked, the rule misses this method.")).
				WithRemediation("Apply authorization uniformly to every HTTP method on a route, and reject "+
					"unknown/unsupported methods with 405. Do not allow-list only a subset of verbs in "+
					"the access-control layer."))
		}
	}
	return out, nil
}

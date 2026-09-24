package checks

import (
	"fmt"

	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// UnauthCheck looks for endpoints that return protected content to an
// unauthenticated visitor. This is the most direct form of Broken Access
// Control: a resource that should require login but does not.
//
// It works by requesting each configured endpoint with no credentials and,
// when authenticated roles exist, comparing that anonymous response to the
// response a logged-in role receives. If the anonymous visitor gets the same
// substantial content a logged-in user does, access control is missing.
type UnauthCheck struct{}

func (UnauthCheck) ID() string    { return "unauth" }
func (UnauthCheck) Title() string { return "Missing authentication (unauthenticated access)" }
func (UnauthCheck) Teaches() string {
	return "Some pages and APIs should only work after you log in. This test asks " +
		"for them WITHOUT logging in. If the server still hands over the real " +
		"content, anyone on the internet can read it. That is Broken Access Control."
}

func (c *UnauthCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()

	// Pick the most privileged role, if any, to use as an authenticated
	// baseline for comparison.
	roles := cfg.SortedRolesByLevel()

	var out []finding.Finding
	for _, ep := range endpointsOrDefault(cfg) {
		if ctx.Client.BudgetExceeded() {
			return out, nil
		}
		u, err := cfg.NormalizeURL(ep.Path)
		if err != nil {
			continue
		}
		method := methodOf(ep)

		// Anonymous request.
		anonResp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
			Method: method, URL: u,
			Headers: anon.Headers, Cookie: anon.Cookie,
		})
		if err != nil {
			ctx.Log.Printf("[unauth] %s %s: %v", method, u, err)
			continue
		}

		if !isGrantedContent(anonResp) {
			continue // properly gated, nothing to report
		}
		if ctx.LooksLikeCatchAll(anonResp) {
			continue // just the server's catch-all/soft-404 page, not a real resource
		}

		// The anonymous visitor got content. Decide how strong the signal is.
		sev := finding.Medium
		conf := "needs-review"
		meaning := c.Teaches()
		evidence := "Anonymous (no credentials) request succeeded: " + evidenceForResponse(anonResp)

		if ep.Sensitive {
			sev = finding.High
		}

		// Strengthen the finding by comparing against a logged-in baseline.
		if len(roles) > 0 {
			top := roles[len(roles)-1]
			if top.Level > 0 {
				authResp, aerr := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
					Method: method, URL: u,
					Headers: top.Headers, Cookie: top.Cookie,
				})
				if aerr == nil && isGrantedContent(authResp) {
					sim := similarity(anonResp.Body, authResp.Body)
					if sim > 0.85 {
						sev = finding.High
						conf = "likely"
						evidence += fmt.Sprintf(
							"; anonymous response is %.0f%% similar to the response for authenticated role %q",
							sim*100, roleLabel(top))
					}
				}
			}
		}

		f := finding.New(c.ID(),
			fmt.Sprintf("Endpoint served to unauthenticated visitor: %s %s", method, ep.Path),
			sev).
			WithURL(u).WithMethod(method).
			WithMeaning(meaning).
			WithEvidence(evidence).
			WithConfidence(conf).
			WithRepro(repro(method, u, anon.Headers,
				"Open a private/incognito window (so you are logged out) and visit the URL. "+
					"If the protected content loads, it is reachable with no authentication.")).
			WithRemediation("Require authentication on this endpoint at the server side. Enforce it " +
				"in middleware or a filter that runs before the handler, deny by default, and never " +
				"rely on the UI hiding a link. Verify the session/token on every request.")
		out = append(out, f)
	}
	return out, nil
}

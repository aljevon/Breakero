package checks

import (
	"fmt"
	"strings"

	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// PrivEscCheck detects vertical privilege escalation: a lower-privileged user
// (or an anonymous visitor) reaching functionality that should be reserved for
// a higher-privileged role such as an administrator.
//
// It needs at least two roles configured. For each endpoint it compares who is
// allowed in. If a role below the endpoint's required level receives the same
// protected content the privileged role does, function-level access control is
// missing.
type PrivEscCheck struct{}

func (PrivEscCheck) ID() string    { return "privesc" }
func (PrivEscCheck) Title() string { return "Vertical privilege escalation" }
func (PrivEscCheck) Teaches() string {
	return "Roles matter: a normal user should not be able to do admin things. " +
		"This test logs in as each role and checks whether a low-privilege role " +
		"can reach a high-privilege feature. If it can, the server is trusting the " +
		"role label in the UI instead of enforcing it."
}

func (c *PrivEscCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	roles := cfg.SortedRolesByLevel()
	if len(roles) < 2 {
		ctx.Log.Printf("[privesc] skipped: needs at least 2 roles (define roles with different levels)")
		return nil, nil
	}
	if len(cfg.Endpoints) == 0 {
		ctx.Log.Printf("[privesc] skipped: needs configured endpoints with min_role set")
		return nil, nil
	}

	top := roles[len(roles)-1]
	var out []finding.Finding

	for _, ep := range cfg.Endpoints {
		if ctx.Client.BudgetExceeded() {
			return out, nil
		}
		u, err := cfg.NormalizeURL(ep.Path)
		if err != nil {
			continue
		}
		method := methodOf(ep)

		// Establish the privileged baseline: the top role should be allowed.
		baseResp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
			Method: method, URL: u, Headers: top.Headers, Cookie: top.Cookie,
		})
		if err != nil || !isGrantedContent(baseResp) {
			continue // cannot establish a privileged baseline; skip
		}

		minLevel := requiredLevel(cfg, ep, top.Level)

		for _, r := range roles {
			if r.Name == top.Name {
				continue
			}
			// Only roles BELOW the required level are interesting here.
			if r.Level >= minLevel {
				continue
			}
			if ctx.Client.BudgetExceeded() {
				return out, nil
			}
			resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
				Method: method, URL: u, Headers: r.Headers, Cookie: r.Cookie,
			})
			if err != nil || !isGrantedContent(resp) {
				continue
			}
			sim := similarity(resp.Body, baseResp.Body)
			if sim < 0.6 && resp.Status != baseResp.Status {
				// Content differs a lot and status differs; likely a different,
				// non-privileged page. Avoid a false positive.
				continue
			}
			sev := finding.High
			if r.Level == 0 {
				sev = finding.Critical // anonymous reaching a privileged feature
			}
			out = append(out, finding.New(c.ID(),
				fmt.Sprintf("Lower-privileged role %q reached %s (needs level >= %d)",
					roleLabel(r), ep.Path, minLevel), sev).
				WithURL(u).WithMethod(method).
				WithMeaning(c.Teaches()).
				WithEvidence(fmt.Sprintf(
					"Role %q (level %d) received protected content: %s; %.0f%% similar to the "+
						"response for privileged role %q (level %d).",
					roleLabel(r), r.Level, evidenceForResponse(resp), sim*100,
					roleLabel(top), top.Level)).
				WithConfidence("likely").
				WithRepro(repro(method, u, map[string]string{"Cookie": "<session for " + roleLabel(r) + ">"},
					"Log in as "+roleLabel(r)+" (a lower-privileged account) and open the URL. "+
						"If the admin-only feature works, the role check is missing on the server.")).
				WithRemediation("Enforce role checks on the server for this action, not just in the UI. "+
					"Use a deny-by-default authorization model and verify the caller's role against the "+
					"required privilege inside the handler (or shared middleware) on every request."))
		}
	}
	return out, nil
}

// requiredLevel returns the minimum privilege level required for an endpoint,
// derived from its MinRole name when set, otherwise the privileged baseline.
func requiredLevel(cfg *config.Config, ep config.Endpoint, fallback int) int {
	if ep.MinRole == "" {
		return fallback
	}
	for _, r := range cfg.Roles {
		if strings.EqualFold(r.Name, ep.MinRole) {
			return r.Level
		}
	}
	return fallback
}

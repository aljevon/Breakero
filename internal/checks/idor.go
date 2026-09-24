package checks

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// IDORCheck tests for Insecure Direct Object References, also called Broken
// Object Level Authorization (BOLA). This is the classic "change the id in the
// URL and see someone else's data" bug.
//
// Two techniques are used, both non-destructive (reads only):
//
//  1. Cross-user access: send one role's request but with another role's object
//     id. If the server returns that other user's object, authorization is
//     missing.
//  2. Neighbor probing: when a role owns a numeric id, try the adjacent ids
//     (id-1, id+1). If they return distinct, valid objects, references are
//     likely guessable and unprotected.
type IDORCheck struct{}

func (IDORCheck) ID() string    { return "idor" }
func (IDORCheck) Title() string { return "IDOR / Broken Object Level Authorization (BOLA)" }
func (IDORCheck) Teaches() string {
	return "Apps often refer to your data by an id, like /account?id=1001. If you can " +
		"change that id to 1002 and see someone else's account, the server forgot to " +
		"check that the object actually belongs to you. This is one of the most common " +
		"and highest-impact access-control bugs."
}

func (c *IDORCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	endpoints := idParamEndpoints(cfg)
	if len(endpoints) == 0 {
		ctx.Log.Printf("[idor] skipped: no endpoints with id_param configured")
		return nil, nil
	}

	var out []finding.Finding
	roles := cfg.Roles

	for _, ep := range endpoints {
		method := methodOf(ep)

		// --- Technique 1: cross-user access ---
		for _, self := range roles {
			for _, other := range roles {
				if self.Name == other.Name {
					continue
				}
				for _, otherID := range other.OwnedIDs {
					if ctx.Client.BudgetExceeded() {
						return out, nil
					}
					u, err := substituteID(cfg, ep, otherID)
					if err != nil {
						continue
					}
					resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
						Method: method, URL: u, Headers: self.Headers, Cookie: self.Cookie,
					})
					if err != nil || !isGrantedContent(resp) {
						continue
					}
					// If the response references the other user's id, it is a
					// strong signal we read their object.
					body := strings.ToLower(resp.BodyString())
					conf := "needs-review"
					if strings.Contains(body, strings.ToLower(otherID)) {
						conf = "likely"
					}
					out = append(out, finding.New(c.ID(),
						fmt.Sprintf("Cross-user object access: %q read object %q owned by %q",
							roleLabel(self), otherID, roleLabel(other)), finding.High).
						WithURL(u).WithMethod(method).
						WithMeaning(c.Teaches()).
						WithEvidence(fmt.Sprintf("Requested as role %q using role %q's id %q: %s",
							roleLabel(self), roleLabel(other), otherID, evidenceForResponse(resp))).
						WithConfidence(conf).
						WithRepro(repro(method, u, map[string]string{"Cookie": "<session for " + roleLabel(self) + ">"},
							"Log in as "+roleLabel(self)+", then open the URL. It carries "+roleLabel(other)+
								"'s id "+otherID+", so if their data loads the ownership check is missing.")).
						WithRemediation("On every object lookup, verify the authenticated user is authorized "+
							"for THAT specific object (ownership or an explicit grant). Do not trust an id from "+
							"the request. Prefer server-side scoping (e.g. WHERE owner_id = current_user) and "+
							"consider unguessable identifiers such as UUIDs."))
				}
			}
		}

		// --- Technique 2: neighbor probing ---
		for _, self := range roles {
			for _, ownID := range self.OwnedIDs {
				n, err := strconv.Atoi(ownID)
				if err != nil {
					continue // non-numeric id; skip neighbor probing
				}
				base, err := substituteID(cfg, ep, ownID)
				if err != nil {
					continue
				}
				baseResp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
					Method: method, URL: base, Headers: self.Headers, Cookie: self.Cookie,
				})
				if err != nil || !isGrantedContent(baseResp) {
					continue
				}
				for _, delta := range []int{-1, 1} {
					if ctx.Client.BudgetExceeded() {
						return out, nil
					}
					neighborID := strconv.Itoa(n + delta)
					nu, err := substituteID(cfg, ep, neighborID)
					if err != nil {
						continue
					}
					resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
						Method: method, URL: nu, Headers: self.Headers, Cookie: self.Cookie,
					})
					if err != nil || !isGrantedContent(resp) {
						continue
					}
					sim := similarity(resp.Body, baseResp.Body)
					// Distinct-but-valid object => guessable references exposed.
					if sim > 0.3 && sim < 0.98 {
						out = append(out, finding.New(c.ID(),
							fmt.Sprintf("Guessable object references: neighbor id %q is readable via %s",
								neighborID, ep.Path), finding.Medium).
							WithURL(nu).WithMethod(method).
							WithMeaning(c.Teaches()).
							WithEvidence(fmt.Sprintf(
								"Role %q owns id %q; adjacent id %q also returned a valid, different object "+
									"(%.0f%% similar). Sequential ids are easy to enumerate.",
								roleLabel(self), ownID, neighborID, sim*100)).
							WithConfidence("needs-review").
							WithRepro(repro(method, nu, map[string]string{"Cookie": "<your session>"},
								"While logged in, open the URL. It uses id "+neighborID+", which you do not own. "+
									"If a valid, different record loads, ids are guessable.")).
							WithRemediation("Enforce per-object authorization and avoid sequential, guessable "+
								"identifiers. Even with UUIDs, always check ownership server-side."))
					}
				}
			}
		}
	}
	return out, nil
}

func idParamEndpoints(cfg *config.Config) []config.Endpoint {
	var eps []config.Endpoint
	for _, e := range cfg.Endpoints {
		if e.IDParam != "" || strings.Contains(e.Path, "{id}") {
			eps = append(eps, e)
		}
	}
	return eps
}

// substituteID builds a URL for an endpoint with the object id set to idVal.
// It supports two styles: a "{id}" placeholder in the path, or a named query
// parameter given by ep.IDParam.
func substituteID(cfg *config.Config, ep config.Endpoint, idVal string) (string, error) {
	path := ep.Path
	if strings.Contains(path, "{id}") {
		path = strings.ReplaceAll(path, "{id}", url.PathEscape(idVal))
		return cfg.NormalizeURL(path)
	}
	full, err := cfg.NormalizeURL(path)
	if err != nil {
		return "", err
	}
	if ep.IDParam == "" {
		return full, nil
	}
	u, err := url.Parse(full)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(ep.IDParam, idVal)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

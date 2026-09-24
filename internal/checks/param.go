package checks

import (
	"fmt"
	"net/url"

	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// ParamPrivilegeCheck looks for access decided by something the client can
// change: a query parameter like ?admin=true, a header like X-User-Role: admin,
// or a cookie like isAdmin=1. When an app reads the user's role or "admin" flag
// straight from the request, anyone can flip it. PortSwigger calls this
// "user role controlled by a request parameter", and it is OWASP A01.
//
// It works on endpoints the server denies (401/403): if adding one of these
// hints turns a denial into access, the app trusted client-supplied state.
type ParamPrivilegeCheck struct{}

func (ParamPrivilegeCheck) ID() string { return "param-privilege" }
func (ParamPrivilegeCheck) Title() string {
	return "Privilege from a request parameter, header or cookie"
}
func (ParamPrivilegeCheck) Teaches() string {
	return "Some apps decide what you can do from something you send them: a URL like " +
		"?admin=true, a header like X-User-Role: admin, or a cookie like isAdmin=1. If " +
		"the server believes it, you can just set it yourself. This test adds those hints " +
		"to blocked requests and sees whether they open up."
}

type privVector struct {
	kind  string // "query", "header", "cookie"
	name  string
	value string
}

var privVectors = []privVector{
	{"query", "admin", "true"},
	{"query", "isAdmin", "true"},
	{"query", "is_admin", "1"},
	{"query", "role", "admin"},
	{"query", "debug", "true"},
	{"query", "access", "1"},
	{"header", "X-User-Role", "admin"},
	{"header", "X-Role", "admin"},
	{"header", "X-Admin", "true"},
	{"header", "X-Is-Admin", "true"},
	{"cookie", "admin", "true"},
	{"cookie", "role", "admin"},
	{"cookie", "isAdmin", "1"},
}

func (c *ParamPrivilegeCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()

	var out []finding.Finding
	for _, ep := range endpointsOrDefault(cfg) {
		if ctx.Client.BudgetExceeded() {
			return out, nil
		}
		base, err := cfg.NormalizeURL(ep.Path)
		if err != nil {
			continue
		}
		resp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
			Method: "GET", URL: base, Headers: anon.Headers, Cookie: anon.Cookie,
		})
		if err != nil {
			continue
		}
		if resp.Status != 401 && resp.Status != 403 {
			continue // only meaningful when the plain request is denied
		}

		for _, v := range privVectors {
			if ctx.Client.BudgetExceeded() {
				return out, nil
			}
			reqURL := base
			headers := map[string]string{}
			for k, val := range anon.Headers {
				headers[k] = val
			}
			cookie := anon.Cookie

			switch v.kind {
			case "query":
				if u, e := url.Parse(base); e == nil {
					q := u.Query()
					q.Set(v.name, v.value)
					u.RawQuery = q.Encode()
					reqURL = u.String()
				}
			case "header":
				headers[v.name] = v.value
			case "cookie":
				if cookie != "" {
					cookie += "; "
				}
				cookie += v.name + "=" + v.value
			}

			vresp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
				Method: "GET", URL: reqURL, Headers: headers, Cookie: cookie,
			})
			if err != nil {
				continue
			}
			if vresp.Status >= 200 && vresp.Status < 400 && !vresp.LooksAuthenticatedGate() {
				desc := describeVector(v)
				repHeaders := map[string]string{}
				if v.kind == "header" {
					repHeaders[v.name] = v.value
				}
				repCookie := ""
				if v.kind == "cookie" {
					repCookie = v.name + "=" + v.value
				}
				out = append(out, finding.New(c.ID(),
					fmt.Sprintf("Access granted by %s on %s", desc, ep.Path), finding.High).
					WithURL(reqURL).WithMethod("GET").
					WithMeaning(c.Teaches()).
					WithEvidence(fmt.Sprintf("The plain request returned HTTP %d (denied), but adding %s "+
						"returned HTTP %d.", resp.Status, desc, vresp.Status)).
					WithConfidence("likely").
					WithRepro(reproWithCookie("GET", reqURL, repHeaders, repCookie,
						"Add "+desc+" to the blocked request (in the browser dev tools, or with the command "+
							"above). If the page opens, the server trusted a value you controlled.")).
					WithRemediation("Never take a user's role or permission from the request itself (query "+
						"string, header, cookie or hidden field). Decide access from the authenticated session "+
						"on the server, checked against a trusted store, on every request."))
				break // one confirmed vector per endpoint is enough
			}
		}
	}
	return out, nil
}

func describeVector(v privVector) string {
	switch v.kind {
	case "query":
		return "query parameter " + v.name + "=" + v.value
	case "header":
		return "header " + v.name + ": " + v.value
	default:
		return "cookie " + v.name + "=" + v.value
	}
}

// reproWithCookie is like repro but can also include a Cookie header.
func reproWithCookie(method, u string, headers map[string]string, cookie, browser string) string {
	h := map[string]string{}
	for k, v := range headers {
		h[k] = v
	}
	if cookie != "" {
		h["Cookie"] = cookie
	}
	return repro(method, u, h, browser)
}

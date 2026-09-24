package checks

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// URLBypassCheck tries to slip past an access-control rule by requesting the
// same resource in a slightly different way. A front-end proxy or framework
// often matches the URL as text ("block /admin"), while the back-end resolves
// it differently, so "/admin/", "/ADMIN", "/admin/.", "/admin%2f", "/admin..;/"
// or a rewrite header can all reach the same handler while dodging the block.
// This is OWASP A01 and a core PortSwigger access-control technique.
//
// It only acts on endpoints the server currently denies (401/403), then reports
// any variation that gets in.
type URLBypassCheck struct{}

func (URLBypassCheck) ID() string    { return "url-bypass" }
func (URLBypassCheck) Title() string { return "Access-control bypass via URL-matching tricks" }
func (URLBypassCheck) Teaches() string {
	return "A blocked address like /admin can sometimes be reached by asking for it " +
		"a little differently: /admin/, /ADMIN, /admin/., /admin%2f, /admin..;/ or by " +
		"telling a proxy a different path in a header. The guard checks the text of the " +
		"URL, but the app resolves it to the same page. This test tries those variations."
}

func (c *URLBypassCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	anon := cfg.AnonymousRole()

	var out []finding.Finding
	seen := map[string]bool{}

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
		// Only interesting when the server explicitly denies the plain path.
		if resp.Status != 401 && resp.Status != 403 {
			continue
		}

		for _, variant := range urlVariants(base, ep.Path) {
			if ctx.Client.BudgetExceeded() {
				return out, nil
			}
			if seen[variant.url+variant.header] {
				continue
			}
			seen[variant.url+variant.header] = true

			headers := map[string]string{}
			for k, v := range anon.Headers {
				headers[k] = v
			}
			if variant.header != "" {
				headers[variant.header] = variant.headerVal
			}
			vresp, err := ctx.Client.Do(ctx.Ctx, httpx.RequestSpec{
				Method: "GET", URL: variant.url, Headers: headers, Cookie: anon.Cookie,
			})
			if err != nil {
				continue
			}
			if vresp.Status >= 200 && vresp.Status < 400 && !vresp.LooksAuthenticatedGate() {
				repHeaders := map[string]string{}
				if variant.header != "" {
					repHeaders[variant.header] = variant.headerVal
				}
				out = append(out, finding.New(c.ID(),
					fmt.Sprintf("Access control bypassed: %s reachable via %s", ep.Path, variant.label),
					finding.High).
					WithURL(variant.url).WithMethod("GET").
					WithMeaning(c.Teaches()).
					WithEvidence(fmt.Sprintf("The plain path returned HTTP %d (denied), but %s returned HTTP %d.",
						resp.Status, variant.label, vresp.Status)).
					WithConfidence("likely").
					WithRepro(repro("GET", variant.url, repHeaders,
						"In a private/incognito window, open the exact address above (the tweaked one). "+
							"If the blocked page loads, the guard can be walked around.")).
					WithRemediation("Do not enforce access control by string-matching the URL at a proxy or "+
						"filter. Canonicalize the path first (resolve case, trailing slashes, encoding, dot and "+
						"semicolon segments) and apply the authorization check on the resolved route, in the "+
						"application, on every request."))
				break // one confirmed bypass per endpoint is enough
			}
		}
	}
	return out, nil
}

type urlVariant struct {
	label     string
	url       string
	header    string
	headerVal string
}

// urlVariants builds the alternative ways to ask for the same path.
func urlVariants(fullURL, path string) []urlVariant {
	u, err := url.Parse(fullURL)
	if err != nil {
		return nil
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	trimmed := strings.TrimSuffix(p, "/")
	swap := func(newPath string) string {
		v := *u
		v.Path = newPath
		return v.String()
	}
	// For header-rewrite tricks we send the request to the site root and put the
	// blocked path in a header some proxies trust.
	root := *u
	root.Path = "/"
	rootURL := root.String()

	var vs []urlVariant
	add := func(label, newPath string) {
		if newPath == p {
			return
		}
		vs = append(vs, urlVariant{label: label + " (" + newPath + ")", url: swap(newPath)})
	}

	if strings.HasSuffix(p, "/") {
		add("no trailing slash", trimmed)
	} else {
		add("trailing slash", p+"/")
	}
	add("uppercase path", strings.ToUpper(p))
	add("mixed prefix", "/"+strings.ToUpper(strings.TrimPrefix(trimmed, "/")))
	add("trailing dot", trimmed+"/.")
	add("double slash", "/"+strings.TrimPrefix(trimmed, "/")+"//")
	add("dot segment", strings.Replace(trimmed, "/", "/./", 1))
	add("encoded slash", trimmed+"%2f")
	add("matrix param", trimmed+";/")
	add("semicolon traversal", trimmed+"/..;/") // classic Spring bypass
	add("trailing space", trimmed+"%20")
	add("json suffix", trimmed+".json")

	// Header-based rewrite (URL matched by an edge proxy, real path in a header).
	for _, h := range []string{"X-Original-URL", "X-Rewrite-URL"} {
		vs = append(vs, urlVariant{
			label: h + ": " + p, url: rootURL, header: h, headerVal: p,
		})
	}
	return vs
}

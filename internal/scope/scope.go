// Package scope enforces which hosts Breakero is allowed to touch.
//
// This is a safety control. A pentest is only legal within an agreed scope.
// Breakero refuses to send any request to a host that is not explicitly listed
// as in-scope, so a mistyped URL or a redirect can never drag the tool onto a
// system you were not authorized to test.
package scope

import (
	"fmt"
	"net/url"
	"strings"
)

// Scope holds the allow/deny lists for target hosts.
type Scope struct {
	// Include is the list of allowed host patterns. A pattern may be an exact
	// host ("app.example.com") or a leading-wildcard suffix ("*.example.com").
	Include []string
	// Exclude is an optional list of host patterns that are always blocked,
	// even if they would otherwise match Include. Useful for carving out a
	// shared subdomain that is out of scope.
	Exclude []string
}

// New builds a Scope from include/exclude patterns, normalizing each entry.
func New(include, exclude []string) *Scope {
	return &Scope{
		Include: normalizeAll(include),
		Exclude: normalizeAll(exclude),
	}
}

func normalizeAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = normalize(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalize lower-cases a pattern and strips any scheme, port, or path so that
// callers can pass loose values like "https://App.Example.com:8443/login".
func normalize(p string) string {
	p = strings.TrimSpace(strings.ToLower(p))
	if p == "" {
		return ""
	}
	// Strip scheme.
	if i := strings.Index(p, "://"); i >= 0 {
		p = p[i+3:]
	}
	// Strip path/query.
	if i := strings.IndexAny(p, "/?#"); i >= 0 {
		p = p[:i]
	}
	// Strip credentials.
	if i := strings.LastIndex(p, "@"); i >= 0 {
		p = p[i+1:]
	}
	// Strip port.
	if i := strings.LastIndex(p, ":"); i >= 0 {
		// Keep IPv6 brackets intact; only strip a trailing :port.
		if !strings.Contains(p[i:], "]") {
			p = p[:i]
		}
	}
	return strings.Trim(p, "[]")
}

// Empty reports whether no include patterns are configured. An empty scope is
// treated as "nothing is allowed", never "everything is allowed".
func (s *Scope) Empty() bool { return len(s.Include) == 0 }

// hostOf extracts the normalized host from a full URL.
func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	h := u.Hostname()
	if h == "" {
		// url.Parse tolerates scheme-less values by treating them as paths.
		return normalize(rawURL), nil
	}
	return strings.ToLower(h), nil
}

func matchPattern(host, pattern string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return host == pattern[2:] || strings.HasSuffix(host, suffix)
	}
	return host == pattern
}

// Allows reports whether a URL is inside the authorized scope.
func (s *Scope) Allows(rawURL string) bool {
	host, err := hostOf(rawURL)
	if err != nil || host == "" {
		return false
	}
	for _, p := range s.Exclude {
		if matchPattern(host, p) {
			return false
		}
	}
	for _, p := range s.Include {
		if matchPattern(host, p) {
			return true
		}
	}
	return false
}

// Check returns a descriptive error when a URL is out of scope, or nil when it
// is allowed. Callers use this to fail loudly rather than silently skipping.
func (s *Scope) Check(rawURL string) error {
	if s.Empty() {
		return fmt.Errorf("scope is empty: refusing to test %q (define an in-scope host first)", rawURL)
	}
	if !s.Allows(rawURL) {
		host, _ := hostOf(rawURL)
		return fmt.Errorf("host %q is OUT OF SCOPE: refusing to send request to %q", host, rawURL)
	}
	return nil
}

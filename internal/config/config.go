// Package config loads and validates Breakero's run configuration.
//
// Configuration can come from a JSON file (for repeatable, multi-role scans)
// and/or command-line flags (for quick one-off scans). The config file format
// is plain JSON so the tool has zero external dependencies and its binaries
// stay small and fast to start.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Role represents an identity Breakero can send requests as. Comparing what
// different roles can reach is how vertical and horizontal privilege problems
// are detected.
//
// Level encodes privilege: a higher number means more privilege. The special
// role named "anonymous" (level 0) represents an unauthenticated visitor.
type Role struct {
	Name    string            `json:"name"`
	Level   int               `json:"level"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookie  string            `json:"cookie,omitempty"`
	// OwnedIDs lists object identifiers that legitimately belong to this role.
	// The IDOR check uses them to attempt cross-user access with another
	// role's credentials.
	OwnedIDs []string `json:"owned_ids,omitempty"`
}

// Endpoint is a single application path to test.
type Endpoint struct {
	Path   string `json:"path"`
	Method string `json:"method,omitempty"`
	// MinRole is the least-privileged role name that should be allowed to use
	// this endpoint. Used to reason about privilege escalation.
	MinRole string `json:"min_role,omitempty"`
	// Sensitive marks endpoints that should never be reachable anonymously.
	Sensitive bool `json:"sensitive,omitempty"`
	// IDParam names a path/query parameter that holds an object reference,
	// enabling IDOR/BOLA testing on this endpoint.
	IDParam string `json:"id_param,omitempty"`
}

// Config is the full run configuration.
type Config struct {
	// Authorized MUST be true. It is the explicit confirmation that the person
	// running Breakero has written permission to test the target.
	Authorized bool `json:"authorized"`

	// BaseURL is the root of the target application, e.g. https://app.test.
	BaseURL string `json:"base_url"`

	// Scope lists the host patterns Breakero may touch. Requests to any other
	// host are refused. If empty, BaseURL's host is used.
	ScopeInclude []string `json:"scope_include,omitempty"`
	ScopeExclude []string `json:"scope_exclude,omitempty"`

	Roles     []Role     `json:"roles,omitempty"`
	Endpoints []Endpoint `json:"endpoints,omitempty"`

	// Checks selects which modules run. Empty means "all".
	Checks []string `json:"checks,omitempty"`

	// Safety and pacing controls.
	RatePerSecond      float64 `json:"rate_per_second,omitempty"`
	MaxRequests        int     `json:"max_requests,omitempty"`
	TimeoutSeconds     int     `json:"timeout_seconds,omitempty"`
	FollowRedirects    bool    `json:"follow_redirects,omitempty"`
	InsecureTLS        bool    `json:"insecure_tls,omitempty"`
	AllowStateChanging bool    `json:"allow_state_changing,omitempty"`
	UserAgent          string  `json:"user_agent,omitempty"`

	// Output controls.
	JSONReport string `json:"json_report,omitempty"`
	HTMLReport string `json:"html_report,omitempty"`
}

// Load reads a JSON config file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	return &c, nil
}

// Timeout returns the per-request timeout as a duration.
func (c *Config) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// ScopeHosts returns the effective in-scope host list, defaulting to the
// BaseURL host when no explicit scope is configured.
func (c *Config) ScopeHosts() []string {
	if len(c.ScopeInclude) > 0 {
		return c.ScopeInclude
	}
	if c.BaseURL == "" {
		return nil
	}
	if u, err := url.Parse(c.BaseURL); err == nil && u.Hostname() != "" {
		return []string{u.Hostname()}
	}
	return nil
}

// AnonymousRole returns the role representing an unauthenticated visitor,
// synthesizing one if the config did not define it.
func (c *Config) AnonymousRole() Role {
	for _, r := range c.Roles {
		if strings.EqualFold(r.Name, "anonymous") || r.Level == 0 {
			return r
		}
	}
	return Role{Name: "anonymous", Level: 0}
}

// SortedRolesByLevel returns roles ordered from least to most privileged.
func (c *Config) SortedRolesByLevel() []Role {
	roles := make([]Role, len(c.Roles))
	copy(roles, c.Roles)
	for i := 1; i < len(roles); i++ {
		for j := i; j > 0 && roles[j-1].Level > roles[j].Level; j-- {
			roles[j-1], roles[j] = roles[j], roles[j-1]
		}
	}
	return roles
}

// Validate checks the config is safe and coherent to run. It deliberately
// fails closed: anything ambiguous about authorization or scope is an error.
func (c *Config) Validate() error {
	if !c.Authorized {
		return fmt.Errorf("refusing to run: 'authorized' is not set to true.\n" +
			"Breakero only tests systems you are permitted to test. Set authorized=true\n" +
			"(config) or pass --i-am-authorized to confirm you have written permission")
	}
	if strings.TrimSpace(c.BaseURL) == "" {
		return fmt.Errorf("base_url is required")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("base_url %q is not a valid absolute URL (include http:// or https://)", c.BaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("base_url scheme %q is not supported (use http or https)", u.Scheme)
	}
	if len(c.ScopeHosts()) == 0 {
		return fmt.Errorf("no in-scope hosts could be determined; set scope_include or a valid base_url")
	}
	if c.RatePerSecond < 0 {
		return fmt.Errorf("rate_per_second cannot be negative")
	}
	if c.RatePerSecond > 50 {
		return fmt.Errorf("rate_per_second %.1f is too aggressive; keep it <= 50 to avoid stressing the target", c.RatePerSecond)
	}
	seen := map[string]bool{}
	for _, r := range c.Roles {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("every role needs a name")
		}
		if seen[strings.ToLower(r.Name)] {
			return fmt.Errorf("duplicate role name %q", r.Name)
		}
		seen[strings.ToLower(r.Name)] = true
	}
	return nil
}

// NormalizeURL joins a possibly-relative path onto the base URL.
func (c *Config) NormalizeURL(path string) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

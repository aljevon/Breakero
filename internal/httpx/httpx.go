// Package httpx provides the single HTTP client every check must use.
//
// It centralizes three safety controls so no individual check can bypass them:
//
//   - Scope enforcement: a request to an out-of-scope host is refused.
//   - Rate limiting: requests are paced so the tool never floods a target.
//     Breakero is an access-control tester, not a load or denial-of-service
//     tool, and the pacing keeps it firmly on that side of the line.
//   - A global request budget: once the configured maximum is reached, no
//     further requests are sent. This bounds the blast radius of any run.
package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aljevon/breakero/internal/scope"
)

// Response is a trimmed view of an HTTP response that checks care about. The
// body is capped so large downloads never blow up memory or logs.
type Response struct {
	Status     int
	StatusText string
	Header     http.Header
	Body       []byte
	BodyLen    int64 // full advertised/streamed length before capping
	Truncated  bool
	Elapsed    time.Duration
	FinalURL   string // after redirects, if any were followed
}

// Options configures a Client.
type Options struct {
	Scope           *scope.Scope
	RatePerSecond   float64       // average requests/second; <=0 means 5/s
	Timeout         time.Duration // per-request timeout
	MaxRequests     int           // global budget; <=0 means unlimited-but-warned
	MaxBodyBytes    int64         // body cap; <=0 means 512 KiB
	UserAgent       string
	FollowRedirects bool
	InsecureTLS     bool // allow self-signed certs on the target (labs, staging)
	ExtraHeaders    map[string]string
}

// Client is a safety-wrapped HTTP client shared by all checks.
type Client struct {
	http    *http.Client
	opts    Options
	scope   *scope.Scope
	limiter *limiter
	count   atomic.Int64
	maxReq  int64
	mu      sync.Mutex
	stopped bool
}

// New builds a Client from Options, applying safe defaults.
func New(opts Options) *Client {
	if opts.RatePerSecond <= 0 {
		opts.RatePerSecond = 5
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 512 * 1024
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "Breakero/1.0 (+authorized-access-control-testing)"
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        100,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.InsecureTLS}, //nolint:gosec // opt-in for authorized lab targets only
	}
	c := &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
	}
	if !opts.FollowRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &Client{
		http:    c,
		opts:    opts,
		scope:   opts.Scope,
		limiter: newLimiter(opts.RatePerSecond),
		maxReq:  int64(opts.MaxRequests),
	}
}

// Count returns how many requests have been sent so far.
func (c *Client) Count() int64 { return c.count.Load() }

// BudgetExceeded reports whether the global request budget is spent.
func (c *Client) BudgetExceeded() bool {
	return c.maxReq > 0 && c.count.Load() >= c.maxReq
}

// RequestSpec describes one request a check wants to make.
type RequestSpec struct {
	Method  string
	URL     string
	Headers map[string]string
	Cookie  string
	Body    string
	// NoRedirect forces this single request not to follow redirects even if
	// the client is otherwise configured to follow them.
	NoRedirect bool
}

// Do performs a request after enforcing every safety control. It returns an
// error (and sends nothing) when the target is out of scope or the budget is
// exhausted.
func (c *Client) Do(ctx context.Context, spec RequestSpec) (*Response, error) {
	if c.scope == nil {
		return nil, fmt.Errorf("internal error: client has no scope configured")
	}
	if err := c.scope.Check(spec.URL); err != nil {
		return nil, err
	}
	if c.BudgetExceeded() {
		return nil, fmt.Errorf("request budget of %d reached: stopping to stay within safe limits", c.maxReq)
	}

	// Pace the request. This is the anti-flood control.
	if err := c.limiter.wait(ctx); err != nil {
		return nil, err
	}
	c.count.Add(1)

	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = http.MethodGet
	}
	var bodyReader io.Reader
	if spec.Body != "" {
		bodyReader = strings.NewReader(spec.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, spec.URL, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	for k, v := range c.opts.ExtraHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range spec.Headers {
		req.Header.Set(k, v)
	}
	if spec.Cookie != "" {
		req.Header.Set("Cookie", spec.Cookie)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, c.opts.MaxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	truncated := int64(len(body)) > c.opts.MaxBodyBytes
	if truncated {
		body = body[:c.opts.MaxBodyBytes]
	}

	// Re-check scope on the final URL in case a followed redirect crossed a
	// host boundary. If it did, we do not return the response body.
	finalURL := resp.Request.URL.String()
	if err := c.scope.Check(finalURL); err != nil {
		return nil, fmt.Errorf("redirect left scope: %w", err)
	}

	return &Response{
		Status:     resp.StatusCode,
		StatusText: resp.Status,
		Header:     resp.Header,
		Body:       body,
		BodyLen:    int64(len(body)),
		Truncated:  truncated,
		Elapsed:    time.Since(start),
		FinalURL:   finalURL,
	}, nil
}

// limiter is a minimal token-bucket rate limiter using only the standard
// library, so Breakero has zero external dependencies.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(perSecond float64) *limiter {
	if perSecond <= 0 {
		perSecond = 5
	}
	return &limiter{interval: time.Duration(float64(time.Second) / perSecond)}
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// BodyString returns the response body as a string for convenience.
func (r *Response) BodyString() string { return string(r.Body) }

// LooksAuthenticatedGate reports whether the response looks like a login wall,
// an auth redirect, or an access-denied page. Checks use this to tell a real
// "access granted" from a "you must log in" response.
func (r *Response) LooksAuthenticatedGate() bool {
	switch r.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return true
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusMovedPermanently:
		loc := strings.ToLower(r.Header.Get("Location"))
		if strings.Contains(loc, "login") || strings.Contains(loc, "signin") ||
			strings.Contains(loc, "auth") || strings.Contains(loc, "sso") {
			return true
		}
	}
	low := strings.ToLower(string(r.Body))
	for _, marker := range []string{"please log in", "please sign in", "login required",
		"access denied", "not authorized", "unauthorized", "forbidden", "session expired"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

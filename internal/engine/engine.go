// Package engine runs the selected checks against a target and collects the
// findings. It is deliberately thin: all safety controls live in httpx and
// scope, and all detection logic lives in the individual checks.
package engine

import (
	"context"
	"log"
	"time"

	"github.com/aljevon/breakero/internal/checks"
	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/finding"
	"github.com/aljevon/breakero/internal/httpx"
)

// Result is the outcome of a full run.
type Result struct {
	Target    string
	Started   time.Time
	Finished  time.Time
	Requests  int64
	Findings  []finding.Finding
	CheckLog  []CheckRun
	ScopeHost []string
}

// CheckRun records what one check did, so the report can show coverage even
// for checks that found nothing.
type CheckRun struct {
	ID       string
	Title    string
	Teaches  string
	Findings int
	Duration time.Duration
	Err      string
}

// Duration returns how long the whole run took.
func (r *Result) Duration() time.Duration { return r.Finished.Sub(r.Started) }

// Run executes the selected checks and returns a Result.
func (r *Runner) Run(ctx context.Context) (*Result, error) {
	res := &Result{
		Target:    r.cfg.BaseURL,
		Started:   time.Now(),
		ScopeHost: r.cfg.ScopeHosts(),
	}

	// Calibrate against a soft-404 / catch-all: some servers answer 200 with
	// content for paths that do not exist. Detecting this up front lets the
	// checks avoid flagging every guessed path as an exposure.
	notFound, catchAll := r.calibrate(ctx)
	if catchAll {
		r.log.Printf("note: target returns success content for non-existent paths " +
			"(catch-all/soft-404); path-guessing findings will be filtered to distinct pages")
	}

	for _, chk := range r.checks {
		if r.client.BudgetExceeded() {
			r.log.Printf("request budget reached; stopping before %q", chk.ID())
			break
		}
		start := time.Now()
		r.log.Printf("running check: %-16s %s", chk.ID(), chk.Title())
		cctx := &checks.Context{
			Ctx:      ctx,
			Client:   r.client,
			Config:   r.cfg,
			Log:      r.log,
			NotFound: notFound,
			CatchAll: catchAll,
		}
		found, err := chk.Run(cctx)
		run := CheckRun{
			ID:       chk.ID(),
			Title:    chk.Title(),
			Teaches:  chk.Teaches(),
			Findings: len(found),
			Duration: time.Since(start),
		}
		if err != nil {
			run.Err = err.Error()
			r.log.Printf("check %q error: %v", chk.ID(), err)
		}
		res.Findings = append(res.Findings, found...)
		res.CheckLog = append(res.CheckLog, run)

		if ctx.Err() != nil {
			r.log.Printf("run cancelled: %v", ctx.Err())
			break
		}
	}

	finding.Sort(res.Findings)
	res.Requests = r.client.Count()
	res.Finished = time.Now()
	return res, nil
}

// Runner ties together a config, HTTP client, and the selected checks.
type Runner struct {
	cfg    *config.Config
	client *httpx.Client
	checks []checks.Check
	log    *log.Logger
}

// NewRunner builds a Runner from an already-validated config.
func NewRunner(cfg *config.Config, client *httpx.Client, selected []checks.Check, logger *log.Logger) *Runner {
	return &Runner{cfg: cfg, client: client, checks: selected, log: logger}
}

// calibrate requests two deliberately random, non-existent paths. If both come
// back as "success" content and look alike, the server has a catch-all handler
// (a soft 404). It returns the baseline response and whether a catch-all was
// detected.
func (r *Runner) calibrate(ctx context.Context) (*httpx.Response, bool) {
	probe := func(p string) *httpx.Response {
		u, err := r.cfg.NormalizeURL(p)
		if err != nil {
			return nil
		}
		resp, err := r.client.Do(ctx, httpx.RequestSpec{Method: "GET", URL: u})
		if err != nil {
			return nil
		}
		return resp
	}
	a := probe("/breakero-not-a-real-path-9x7q2")
	b := probe("/definitely-missing-4k1p8-breakero")
	granted := func(resp *httpx.Response) bool {
		return resp != nil && resp.Status >= 200 && resp.Status < 400 && !resp.LooksAuthenticatedGate()
	}
	if granted(a) && granted(b) && checks.BodySimilarity(a.Body, b.Body) > 0.9 {
		return a, true
	}
	if a != nil {
		return a, false
	}
	return b, false
}

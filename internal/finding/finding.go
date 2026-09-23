// Package finding defines the data model for a Broken Access Control finding.
//
// Every check in Breakero reports its results as one or more Finding values.
// A Finding is written to be understandable by someone new to security: it
// carries a plain-language explanation, evidence, an impact statement, and
// concrete remediation guidance tied back to OWASP A01:2025.
package finding

import (
	"sort"
	"strings"
	"time"
)

// Severity expresses how serious a finding is.
type Severity int

const (
	// Info is not a vulnerability, just something worth knowing.
	Info Severity = iota
	// Low is a minor issue or a weak signal that needs manual confirmation.
	Low
	// Medium is a real access-control weakness with limited impact.
	Medium
	// High is a clear Broken Access Control issue.
	High
	// Critical is a severe, easily exploited access-control failure.
	Critical
)

// String returns the human label for a severity.
func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "INFO"
	}
}

// Color returns an ANSI color code used for terminal output.
func (s Severity) Color() string {
	switch s {
	case Critical:
		return "\033[1;35m" // bright magenta
	case High:
		return "\033[1;31m" // bright red
	case Medium:
		return "\033[1;33m" // bright yellow
	case Low:
		return "\033[1;36m" // bright cyan
	default:
		return "\033[1;37m" // bright white
	}
}

// Rank returns a numeric weight so findings can be sorted most-serious first.
func (s Severity) Rank() int { return int(s) }

// Finding is a single result produced by a check.
type Finding struct {
	// Check is the short id of the module that produced this finding.
	Check string `json:"check"`
	// Title is a one-line summary of what was found.
	Title string `json:"title"`
	// Severity ranks how serious the finding is.
	Severity Severity `json:"severity"`
	// SeverityLabel mirrors Severity as text so JSON reports are readable.
	SeverityLabel string `json:"severity_label"`
	// URL is the request target the finding relates to.
	URL string `json:"url"`
	// Method is the HTTP method used, when relevant.
	Method string `json:"method,omitempty"`
	// WhatItMeans explains, in plain language, why this matters. Aimed at
	// people who are new to access-control testing.
	WhatItMeans string `json:"what_it_means"`
	// Evidence is the concrete observation that supports the finding
	// (status codes, response sizes, reflected headers, and so on).
	Evidence string `json:"evidence"`
	// Remediation is how a developer should fix the underlying issue.
	Remediation string `json:"remediation"`
	// Reference points back to the relevant OWASP A01:2025 guidance.
	Reference string `json:"reference"`
	// Confidence is a rough label: "confirmed", "likely", or "needs-review".
	Confidence string `json:"confidence"`
	// Time is when the finding was recorded.
	Time time.Time `json:"time"`
}

// New builds a Finding and fills in the derived fields.
func New(check, title string, sev Severity) Finding {
	return Finding{
		Check:         check,
		Title:         title,
		Severity:      sev,
		SeverityLabel: sev.String(),
		Confidence:    "needs-review",
		Reference:     "OWASP Top 10 2025 - A01: Broken Access Control (https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)",
		Time:          time.Now(),
	}
}

// WithURL sets the URL and returns the finding for chaining.
func (f Finding) WithURL(u string) Finding { f.URL = u; return f }

// WithMethod sets the HTTP method and returns the finding for chaining.
func (f Finding) WithMethod(m string) Finding { f.Method = m; return f }

// WithMeaning sets the plain-language explanation.
func (f Finding) WithMeaning(s string) Finding { f.WhatItMeans = s; return f }

// WithEvidence sets the evidence text.
func (f Finding) WithEvidence(s string) Finding { f.Evidence = s; return f }

// WithRemediation sets the remediation text.
func (f Finding) WithRemediation(s string) Finding { f.Remediation = s; return f }

// WithConfidence sets the confidence label.
func (f Finding) WithConfidence(s string) Finding { f.Confidence = s; return f }

// Sort orders findings most-serious first, then by check name and URL, so
// reports are stable and the important issues appear at the top.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		if fs[i].Check != fs[j].Check {
			return fs[i].Check < fs[j].Check
		}
		return fs[i].URL < fs[j].URL
	})
}

// Counts returns how many findings fall into each severity bucket.
func Counts(fs []Finding) map[Severity]int {
	m := map[Severity]int{}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// Summary renders a compact one-line count string, e.g.
// "2 critical, 1 high, 3 medium".
func Summary(fs []Finding) string {
	c := Counts(fs)
	order := []Severity{Critical, High, Medium, Low, Info}
	var parts []string
	for _, s := range order {
		if c[s] > 0 {
			parts = append(parts, strings.ToLower(s.String())+": "+itoa(c[s]))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

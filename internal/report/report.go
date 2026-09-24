// Package report renders a run's results to the terminal, to JSON, and to a
// self-contained HTML file. The output is written for people who are new to
// access-control testing: every finding is explained in plain language and
// paired with a concrete fix.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"

	"github.com/aljevon/breakero/internal/engine"
	"github.com/aljevon/breakero/internal/finding"
)

const reset = "\033[0m"
const dim = "\033[2m"
const bold = "\033[1m"

// Console prints a human-readable report to stdout.
func Console(res *engine.Result, color bool) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + reset
	}

	fmt.Println()
	fmt.Println(c(bold, "══════════════════════════════════════════════════════════════"))
	fmt.Println(c(bold, "  Breakero — Broken Access Control report (OWASP A01:2025)"))
	fmt.Println(c(bold, "══════════════════════════════════════════════════════════════"))
	fmt.Printf("  Target      : %s\n", res.Target)
	fmt.Printf("  In scope    : %s\n", strings.Join(res.ScopeHost, ", "))
	fmt.Printf("  Requests    : %d\n", res.Requests)
	fmt.Printf("  Duration    : %s\n", res.Duration().Round(time.Millisecond))
	fmt.Printf("  Findings    : %s\n", finding.Summary(res.Findings))
	fmt.Println()

	if len(res.Findings) == 0 {
		fmt.Println(c(dim, "  No access-control issues were detected by the checks that ran."))
		fmt.Println(c(dim, "  This is not a guarantee the target is secure — it means these"))
		fmt.Println(c(dim, "  specific tests did not trigger. Review the coverage list below."))
	}

	for i, f := range res.Findings {
		sevTag := f.Severity.String()
		if color {
			sevTag = f.Severity.Color() + sevTag + reset
		}
		fmt.Printf("\n  [%d] %s  %s\n", i+1, sevTag, c(bold, f.Title))
		if f.URL != "" {
			m := f.Method
			if m == "" {
				m = "GET"
			}
			fmt.Printf("      %s %s\n", m, f.URL)
		}
		fmt.Printf("      %s %s\n", c(dim, "confidence:"), f.Confidence)
		printWrapped("      what it means: ", f.WhatItMeans)
		printWrapped("      evidence:      ", f.Evidence)
		printWrapped("      how to fix:    ", f.Remediation)
		if strings.TrimSpace(f.Repro) != "" {
			fmt.Printf("      %s\n", c(dim, "reproduce:"))
			for _, line := range strings.Split(f.Repro, "\n") {
				fmt.Printf("        %s\n", line)
			}
		}
	}

	fmt.Println()
	fmt.Println(c(bold, "  ── Coverage (what was tested) ──"))
	for _, run := range res.CheckLog {
		status := fmt.Sprintf("%d finding(s)", run.Findings)
		if run.Err != "" {
			status = "error: " + run.Err
		}
		fmt.Printf("    • %-16s %-40s %s\n", run.ID, truncate(run.Title, 40), status)
	}
	fmt.Println()
	fmt.Println(c(dim, "  Reference: OWASP Top 10 2025 — A01 Broken Access Control"))
	fmt.Println(c(dim, "  https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/"))
	fmt.Println()
}

func printWrapped(prefix, text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	const width = 76
	indent := strings.Repeat(" ", len(prefix))
	words := strings.Fields(text)
	line := prefix
	first := true
	for _, w := range words {
		if len(line)+len(w)+1 > width && !first {
			fmt.Println(line)
			line = indent + w
		} else {
			if first {
				line += w
				first = false
			} else {
				line += " " + w
			}
		}
	}
	if strings.TrimSpace(line) != "" {
		fmt.Println(line)
	}
}

// jsonReport is the on-disk JSON shape.
type jsonReport struct {
	Tool      string            `json:"tool"`
	Version   string            `json:"version"`
	Standard  string            `json:"standard"`
	Reference string            `json:"reference"`
	Target    string            `json:"target"`
	Scope     []string          `json:"scope"`
	Started   time.Time         `json:"started"`
	Finished  time.Time         `json:"finished"`
	Requests  int64             `json:"requests"`
	Summary   map[string]int    `json:"summary"`
	Findings  []finding.Finding `json:"findings"`
	Coverage  []engine.CheckRun `json:"coverage"`
}

// RenderJSON builds the machine-readable report as bytes.
func RenderJSON(res *engine.Result, version string) ([]byte, error) {
	summary := map[string]int{}
	for sev, n := range finding.Counts(res.Findings) {
		summary[strings.ToLower(sev.String())] = n
	}
	rep := jsonReport{
		Tool:      "Breakero",
		Version:   version,
		Standard:  "OWASP Top 10 2025 - A01 Broken Access Control",
		Reference: "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/",
		Target:    res.Target,
		Scope:     res.ScopeHost,
		Started:   res.Started,
		Finished:  res.Finished,
		Requests:  res.Requests,
		Summary:   summary,
		Findings:  res.Findings,
		Coverage:  res.CheckLog,
	}
	return json.MarshalIndent(rep, "", "  ")
}

// WriteJSON writes a machine-readable report to path.
func WriteJSON(res *engine.Result, path, version string) error {
	data, err := RenderJSON(res, version)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// WriteHTML writes a self-contained (no external assets) HTML report to path.
func WriteHTML(res *engine.Result, path, version string) error {
	return os.WriteFile(path, RenderHTML(res, version), 0o644)
}

// RenderHTML builds a self-contained (no external assets) HTML report.
func RenderHTML(res *engine.Result, version string) []byte {
	var b strings.Builder
	esc := html.EscapeString

	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString(`<title>Breakero — Broken Access Control report</title>`)
	b.WriteString("<style>" + reportCSS + "</style></head><body>")

	b.WriteString(`<header><h1>Breakero</h1>`)
	b.WriteString(`<p class="sub">Broken Access Control report · OWASP Top 10 2025 · A01</p></header>`)

	// Meta panel.
	b.WriteString(`<section class="card meta"><table>`)
	row := func(k, v string) { b.WriteString("<tr><th>" + esc(k) + "</th><td>" + esc(v) + "</td></tr>") }
	row("Target", res.Target)
	row("In scope", strings.Join(res.ScopeHost, ", "))
	row("Requests sent", fmt.Sprintf("%d", res.Requests))
	row("Started", res.Started.Format(time.RFC3339))
	row("Duration", res.Duration().Round(time.Millisecond).String())
	row("Findings", finding.Summary(res.Findings))
	row("Tool version", version)
	b.WriteString(`</table></section>`)

	// Severity summary chips.
	b.WriteString(`<section class="chips">`)
	counts := finding.Counts(res.Findings)
	for _, s := range []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info} {
		b.WriteString(fmt.Sprintf(`<span class="chip sev-%s">%s: %d</span>`,
			strings.ToLower(s.String()), esc(s.String()), counts[s]))
	}
	b.WriteString(`</section>`)

	// Learning note.
	b.WriteString(`<section class="card learn"><h2>New to this? Read me first</h2>`)
	b.WriteString(`<p>Broken Access Control means the application lets someone do or see ` +
		`something they should not be allowed to. Each finding below explains, in plain ` +
		`language, what was observed, why it matters, and how a developer fixes it. ` +
		`Findings marked <em>needs-review</em> should be confirmed by hand before you report ` +
		`them, since automated tools can be fooled by unusual apps.</p></section>`)

	if len(res.Findings) == 0 {
		b.WriteString(`<section class="card"><p>No access-control issues were detected by the ` +
			`checks that ran. This is not proof the target is secure; review the coverage list ` +
			`to see what was and was not tested.</p></section>`)
	}

	for i, f := range res.Findings {
		sev := strings.ToLower(f.Severity.String())
		b.WriteString(`<section class="card finding sev-border-` + sev + `">`)
		b.WriteString(fmt.Sprintf(`<div class="fhead"><span class="chip sev-%s">%s</span>`,
			sev, esc(f.Severity.String())))
		b.WriteString(fmt.Sprintf(`<h3>%d. %s</h3></div>`, i+1, esc(f.Title)))
		if f.URL != "" {
			m := f.Method
			if m == "" {
				m = "GET"
			}
			b.WriteString(`<p class="url"><code>` + esc(m) + " " + esc(f.URL) + `</code></p>`)
		}
		b.WriteString(`<p class="conf">Confidence: <strong>` + esc(f.Confidence) +
			`</strong> · Module: <code>` + esc(f.Check) + `</code></p>`)
		field(&b, "What it means", f.WhatItMeans)
		field(&b, "Evidence", f.Evidence)
		field(&b, "How to fix", f.Remediation)
		if strings.TrimSpace(f.Repro) != "" {
			b.WriteString(`<div class="field"><span class="flabel">How to reproduce (cross-check by hand)</span><pre class="repro">` +
				esc(f.Repro) + `</pre></div>`)
		}
		b.WriteString(`<p class="ref">` + esc(f.Reference) + `</p>`)
		b.WriteString(`</section>`)
	}

	// Coverage.
	b.WriteString(`<section class="card"><h2>Coverage: what was tested</h2><table class="cov"><tr>` +
		`<th>Module</th><th>Description</th><th>Result</th></tr>`)
	for _, run := range res.CheckLog {
		result := fmt.Sprintf("%d finding(s)", run.Findings)
		if run.Err != "" {
			result = "error: " + run.Err
		}
		b.WriteString("<tr><td><code>" + esc(run.ID) + "</code></td><td>" + esc(run.Title) +
			"</td><td>" + esc(result) + "</td></tr>")
	}
	b.WriteString(`</table></section>`)

	// Verify-first note.
	b.WriteString(`<section class="card"><h2>Verify before you trust</h2><p>These results come from an ` +
		`automated scanner. Treat them as leads, not conclusions. Every finding can be a false positive, and ` +
		`a clean scan is not proof of security. Confirm each one by hand using its "how to reproduce" steps, ` +
		`then dig deeper with manual testing before you report anything. Only test what you are allowed to test.</p></section>`)

	// References.
	b.WriteString(`<section class="card"><h2>References</h2><ul>`)
	for _, r := range [][2]string{
		{"OWASP Top 10 2025 - A01 Broken Access Control", "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/"},
		{"PortSwigger - Access control vulnerabilities", "https://portswigger.net/web-security/access-control"},
		{"PortSwigger - IDOR", "https://portswigger.net/web-security/access-control/idor"},
		{"OWASP Web Security Testing Guide - Authorization", "https://owasp.org/www-project-web-security-testing-guide/"},
		{"CWE-284 - Improper Access Control", "https://cwe.mitre.org/data/definitions/284.html"},
		{"CWE-639 - Authorization Bypass Through User-Controlled Key", "https://cwe.mitre.org/data/definitions/639.html"},
	} {
		b.WriteString(`<li><a href="` + esc(r[1]) + `">` + esc(r[0]) + `</a></li>`)
	}
	b.WriteString(`</ul></section>`)

	b.WriteString(`<footer><p>Generated by Breakero for authorized security testing. ` +
		`github.com/aljevon</p></footer>`)
	b.WriteString(`</body></html>`)

	return []byte(b.String())
}

func field(b *strings.Builder, label, val string) {
	if strings.TrimSpace(val) == "" {
		return
	}
	b.WriteString(`<div class="field"><span class="flabel">` + html.EscapeString(label) +
		`</span><p>` + html.EscapeString(val) + `</p></div>`)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

const reportCSS = `
:root{--bg:#0b0b0c;--card:#0f0f11;--ink:#e8e8ea;--muted:#9a9aa2;--line:#26262b;
--crit:#f2860a;--high:#f2860a;--med:#cfcfd4;--low:#8a8a92;--info:#6a6a72;--accent:#f2860a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.55 ui-monospace,"SFMono-Regular","JetBrains Mono",Menlo,Consolas,monospace;padding:0 16px 64px}
header{max-width:900px;margin:0 auto;padding:32px 0 8px}
h1{margin:0;font-size:30px;letter-spacing:.5px}
.sub{color:var(--muted);margin:4px 0 0}
section{max-width:900px;margin:16px auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:18px 20px}
.meta table{width:100%;border-collapse:collapse}
.meta th{text-align:left;color:var(--muted);font-weight:600;width:150px;padding:4px 8px;vertical-align:top}
.meta td{padding:4px 8px}
.chips{display:flex;gap:8px;flex-wrap:wrap;max-width:900px;margin:12px auto}
.chip{display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:700;color:#0b0d12}
.sev-critical{background:var(--crit);color:#0a0a0a}
.sev-high{background:transparent;border:1px solid var(--high);color:var(--high)}
.sev-medium{background:transparent;border:1px solid var(--line);color:var(--med)}
.sev-low{background:transparent;border:1px solid var(--line);color:var(--low)}
.sev-info{background:transparent;border:1px solid var(--line);color:var(--info)}
.learn p{color:var(--ink)}
.finding{border-left:5px solid var(--line)}
.sev-border-critical{border-left-color:var(--crit)}
.sev-border-high{border-left-color:var(--high)}
.sev-border-medium{border-left-color:var(--med)}
.sev-border-low{border-left-color:var(--low)}
.sev-border-info{border-left-color:var(--info)}
.fhead{display:flex;align-items:center;gap:10px}
.fhead h3{margin:0;font-size:18px}
.url code{background:#0b0d12;padding:4px 8px;border-radius:4px;display:inline-block;word-break:break-all}
.conf{color:var(--muted);font-size:13px;margin:6px 0}
.field{margin:10px 0}
.flabel{display:block;text-transform:uppercase;font-size:11px;letter-spacing:.6px;color:var(--accent);font-weight:700;margin-bottom:2px}
.field p{margin:0}
.repro{white-space:pre-wrap;word-break:break-word;background:#0b0d12;border:1px solid var(--line);border-radius:4px;padding:10px 12px;margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:#c9cde0}
.ref{color:var(--muted);font-size:12px;margin-top:12px}
.cov{width:100%;border-collapse:collapse}
.cov th,.cov td{text-align:left;border-bottom:1px solid var(--line);padding:6px 8px;font-size:14px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
a{color:var(--accent)}
footer{max-width:900px;margin:24px auto 0;color:var(--muted);font-size:13px}
`

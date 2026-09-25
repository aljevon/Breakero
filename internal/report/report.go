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

// riskLevel returns the overall risk label for a set of findings: the highest
// severity present, or "None" when the scan came back clean.
func riskLevel(fs []finding.Finding) (label, class string) {
	c := finding.Counts(fs)
	switch {
	case c[finding.Critical] > 0:
		return "Critical", "critical"
	case c[finding.High] > 0:
		return "High", "high"
	case c[finding.Medium] > 0:
		return "Medium", "medium"
	case c[finding.Low] > 0:
		return "Low", "low"
	case c[finding.Info] > 0:
		return "Informational", "info"
	default:
		return "No issues found", "none"
	}
}

// RenderHTML builds a self-contained (no external assets) HTML report, laid out
// as a professional security-assessment document: a fixed masthead with an
// elegant contents dropdown, an executive summary, a risk overview, a navigable
// findings index, detailed findings, coverage, methodology and references.
func RenderHTML(res *engine.Result, version string) []byte {
	var b strings.Builder
	esc := html.EscapeString
	counts := finding.Counts(res.Findings)
	sevOrder := []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info}
	fid := func(i int) string { return fmt.Sprintf("BRK-%03d", i+1) }
	total := len(res.Findings)
	rlLabel, rlClass := riskLevel(res.Findings)
	dateStr := res.Started.Format("02 January 2006, 15:04 MST")

	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString(`<title>Breakero — Access Control Assessment</title>`)
	b.WriteString("<style>" + reportCSS + "</style></head><body><a id=\"top\"></a>")

	// ---- Fixed masthead with contents dropdown ----
	b.WriteString(`<header class="mast"><div class="mast-in">`)
	b.WriteString(`<div class="brand"><span class="mark">◆</span> Breakero <span class="brand-sub">security assessment</span></div>`)
	b.WriteString(`<div class="mast-tools"><span class="classif">Confidential</span>`)
	b.WriteString(`<details class="menu"><summary>Contents</summary><nav class="menu-panel">`)
	menuLink := func(href, text string) { b.WriteString(`<a href="` + href + `">` + esc(text) + `</a>`) }
	menuLink("#summary", "Executive summary")
	menuLink("#risk", "Risk overview")
	menuLink("#index", "Findings index")
	if total > 0 {
		b.WriteString(`<div class="menu-group">Findings</div>`)
		for i, f := range res.Findings {
			sev := strings.ToLower(f.Severity.String())
			b.WriteString(`<a href="#f-` + fid(i) + `" class="menu-f"><span class="mdot sev-cell-` + sev + `"></span>` +
				`<span class="mfid">` + fid(i) + `</span><span class="mftitle">` + esc(f.Title) + `</span></a>`)
		}
	}
	menuLink("#coverage", "Test coverage")
	menuLink("#method", "Methodology & scope")
	menuLink("#verify", "Verification note")
	menuLink("#refs", "References")
	b.WriteString(`</nav></details></div></div></header>`)

	b.WriteString(`<main>`)

	// ---- Cover block ----
	b.WriteString(`<section class="cover">`)
	b.WriteString(`<div class="doctype">Security Assessment Report</div>`)
	b.WriteString(`<h1>Broken Access Control Assessment</h1>`)
	b.WriteString(`<p class="std">OWASP Top 10 2025 &middot; A01 Broken Access Control</p>`)
	b.WriteString(`<div class="cover-grid">`)
	cov := func(k, v string) {
		b.WriteString(`<div class="cg"><span class="cg-k">` + esc(k) + `</span><span class="cg-v">` + esc(v) + `</span></div>`)
	}
	cov("Target", res.Target)
	cov("Scope", strings.Join(res.ScopeHost, ", "))
	cov("Assessment date", dateStr)
	cov("Duration", res.Duration().Round(time.Millisecond).String())
	cov("Requests sent", fmt.Sprintf("%d", res.Requests))
	cov("Engine version", "Breakero v"+version)
	b.WriteString(`<div class="cg cg-risk risk-` + rlClass + `"><span class="cg-k">Overall risk</span><span class="cg-v">` + esc(rlLabel) + `</span></div>`)
	b.WriteString(`</div></section>`)

	// ---- Executive summary ----
	b.WriteString(`<section id="summary" class="block"><div class="block-num">01</div><h2>Executive summary</h2>`)
	var narr string
	switch {
	case counts[finding.Critical] > 0 || counts[finding.High] > 0:
		hi := counts[finding.Critical] + counts[finding.High]
		narr = fmt.Sprintf(`This assessment evaluated <b>%s</b> for Broken Access Control weaknesses (OWASP Top 10 2025, category A01). `+
			`Across %d automated requests, Breakero identified <b>%d finding(s)</b>: %s. `+
			`<b>%d high-priority issue(s)</b> warrant prompt remediation, as they may allow unauthorized users to reach `+
			`data or actions that should be restricted. Each item below is documented with evidence, business impact and a concrete fix, `+
			`and should be confirmed by hand before it is reported to the asset owner.`,
			esc(res.Target), res.Requests, total, esc(finding.Summary(res.Findings)), hi)
	case total > 0:
		narr = fmt.Sprintf(`This assessment evaluated <b>%s</b> for Broken Access Control weaknesses (OWASP Top 10 2025, category A01). `+
			`Across %d automated requests, Breakero recorded <b>%d finding(s)</b>: %s. `+
			`No critical or high-risk access-control failures were confirmed, but the items below merit review and manual verification.`,
			esc(res.Target), res.Requests, total, esc(finding.Summary(res.Findings)))
	default:
		narr = fmt.Sprintf(`This assessment evaluated <b>%s</b> for Broken Access Control weaknesses (OWASP Top 10 2025, category A01). `+
			`Across %d automated requests, the checks that ran did not confirm any access-control issues. `+
			`This is not a guarantee of security: automated coverage is limited, and manual testing is recommended before drawing conclusions. `+
			`See the test-coverage section for exactly what was and was not exercised.`,
			esc(res.Target), res.Requests)
	}
	b.WriteString(`<div class="riskbar risk-` + rlClass + `"><span class="riskbar-k">Overall risk rating</span><span class="riskbar-v">` + esc(rlLabel) + `</span></div>`)
	b.WriteString(`<p class="lead">` + narr + `</p>`)
	// Severity stat grid.
	b.WriteString(`<div class="statgrid">`)
	for _, s := range sevOrder {
		sev := strings.ToLower(s.String())
		b.WriteString(`<div class="stat sev-cell-` + sev + `"><span class="stat-n">` + fmt.Sprintf("%d", counts[s]) +
			`</span><span class="stat-l">` + esc(titleCase(s.String())) + `</span></div>`)
	}
	b.WriteString(`</div></section>`)

	// ---- Risk overview: distribution bars ----
	b.WriteString(`<section id="risk" class="block"><div class="block-num">02</div><h2>Risk overview</h2>`)
	b.WriteString(`<p class="muted">Distribution of findings by severity. Bars are scaled to the largest category.</p>`)
	max := 1
	for _, s := range sevOrder {
		if counts[s] > max {
			max = counts[s]
		}
	}
	b.WriteString(`<div class="dist">`)
	for _, s := range sevOrder {
		sev := strings.ToLower(s.String())
		w := counts[s] * 100 / max
		b.WriteString(`<div class="dist-row"><span class="dist-l">` + esc(titleCase(sev)) + `</span>` +
			`<span class="dist-track"><i class="dist-bar sev-cell-` + sev + `" style="width:` + fmt.Sprintf("%d", w) + `%"></i></span>` +
			`<span class="dist-n">` + fmt.Sprintf("%d", counts[s]) + `</span></div>`)
	}
	b.WriteString(`</div></section>`)

	// ---- Findings index (navigable table) ----
	b.WriteString(`<section id="index" class="block"><div class="block-num">03</div><h2>Findings index</h2>`)
	if total == 0 {
		b.WriteString(`<p class="muted">No findings to index. The scan did not confirm any access-control issues.</p>`)
	} else {
		b.WriteString(`<p class="muted">` + fmt.Sprintf("%d", total) + ` finding(s). Select any row to jump to its detail.</p>`)
		b.WriteString(`<table class="idx"><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Endpoint</th><th>Confidence</th></tr></thead><tbody>`)
		for i, f := range res.Findings {
			sev := strings.ToLower(f.Severity.String())
			ep := f.URL
			if ep == "" {
				ep = "—"
			}
			b.WriteString(`<tr onclick="location.hash='f-` + fid(i) + `'">` +
				`<td class="mono">` + fid(i) + `</td>` +
				`<td><span class="badge sev-` + sev + `">` + esc(f.Severity.String()) + `</span></td>` +
				`<td><a href="#f-` + fid(i) + `">` + esc(f.Title) + `</a></td>` +
				`<td class="mono ep">` + esc(ep) + `</td>` +
				`<td class="mono">` + esc(f.Confidence) + `</td></tr>`)
		}
		b.WriteString(`</tbody></table>`)
	}
	b.WriteString(`</section>`)

	// ---- Detailed findings ----
	b.WriteString(`<section id="findings" class="block"><div class="block-num">04</div><h2>Detailed findings</h2>`)
	if total == 0 {
		b.WriteString(`<div class="clean"><h3>No access-control issues were confirmed</h3>` +
			`<p class="muted">The checks that ran did not trigger. This is not proof the target is secure — ` +
			`review the coverage section for what was tested, and follow up with manual testing.</p></div>`)
	}
	for i, f := range res.Findings {
		sev := strings.ToLower(f.Severity.String())
		b.WriteString(`<article id="f-` + fid(i) + `" class="finding sev-edge-` + sev + `">`)
		b.WriteString(`<div class="fhead"><div class="fhead-l"><span class="fid">` + fid(i) + `</span>` +
			`<span class="badge sev-` + sev + `">` + esc(f.Severity.String()) + `</span></div>` +
			`<a class="fhead-top" href="#top">↑ top</a></div>`)
		b.WriteString(`<h3>` + esc(f.Title) + `</h3>`)
		// Metadata grid.
		m := f.Method
		if m == "" && f.URL != "" {
			m = "GET"
		}
		b.WriteString(`<div class="meta-grid">`)
		mg := func(k, v string, mono bool) {
			cls := "mg-v"
			if mono {
				cls += " mono"
			}
			b.WriteString(`<div class="mg"><span class="mg-k">` + esc(k) + `</span><span class="` + cls + `">` + esc(v) + `</span></div>`)
		}
		if f.URL != "" {
			mg("Endpoint", strings.TrimSpace(m+" "+f.URL), true)
		}
		mg("Module", f.Check, true)
		mg("Confidence", f.Confidence, false)
		mg("Severity", titleCase(f.Severity.String()), false)
		b.WriteString(`</div>`)
		field(&b, "Description & business impact", f.WhatItMeans)
		field(&b, "Evidence", f.Evidence)
		field(&b, "Recommended remediation", f.Remediation)
		if strings.TrimSpace(f.Repro) != "" {
			b.WriteString(`<div class="field"><span class="flabel">Reproduction &mdash; confirm by hand</span><pre class="repro">` +
				esc(f.Repro) + `</pre></div>`)
		}
		if strings.TrimSpace(f.Reference) != "" {
			b.WriteString(`<p class="ref"><span class="flabel">Reference</span>` + esc(f.Reference) + `</p>`)
		}
		b.WriteString(`</article>`)
	}
	b.WriteString(`</section>`)

	// ---- Coverage ----
	b.WriteString(`<section id="coverage" class="block"><div class="block-num">05</div><h2>Test coverage</h2>`)
	b.WriteString(`<p class="muted">Every check that ran, and what it returned. Modules that reported nothing still exercised the target.</p>`)
	b.WriteString(`<table class="cov"><thead><tr><th>Module</th><th>Description</th><th>Result</th></tr></thead><tbody>`)
	for _, run := range res.CheckLog {
		result := fmt.Sprintf("%d finding(s)", run.Findings)
		rcls := "ok"
		if run.Err != "" {
			result = "error: " + run.Err
			rcls = "err"
		} else if run.Findings > 0 {
			rcls = "hit"
		}
		b.WriteString(`<tr><td class="mono">` + esc(run.ID) + `</td><td>` + esc(run.Title) +
			`</td><td class="res-` + rcls + `">` + esc(result) + `</td></tr>`)
	}
	b.WriteString(`</tbody></table></section>`)

	// ---- Methodology & scope ----
	b.WriteString(`<section id="method" class="block"><div class="block-num">06</div><h2>Methodology &amp; scope</h2>`)
	b.WriteString(`<p>Breakero performs automated, read-only access-control testing aligned with OWASP Top 10 2025 category A01 ` +
		`and techniques from the PortSwigger Web Security Academy. Testing is confined to the authorized scope shown on the cover ` +
		`(<span class="mono">` + esc(strings.Join(res.ScopeHost, ", ")) + `</span>); no other host is touched. The engine calibrates ` +
		`against the target's not-found behavior to reduce false positives, applies a request rate limit, and defaults to safe ` +
		`(non-state-changing) methods. Findings are automated leads: each must be confirmed manually before it is treated as a ` +
		`confirmed vulnerability.</p>`)
	b.WriteString(`<div class="sevkey"><span class="flabel">Severity model</span><ul>` +
		`<li><b>Critical / High</b> — a clear access-control failure that likely exposes restricted data or actions; remediate promptly.</li>` +
		`<li><b>Medium</b> — a real weakness with limited or conditional impact.</li>` +
		`<li><b>Low / Informational</b> — a weak signal or hardening opportunity; verify before reporting.</li></ul></div>`)
	b.WriteString(`</section>`)

	// ---- Verify-first note ----
	b.WriteString(`<section id="verify" class="block"><div class="block-num">07</div><h2>Verification note</h2>`)
	b.WriteString(`<div class="callout"><p>These results come from an automated scanner. Treat them as leads, not conclusions. ` +
		`Every finding can be a false positive, and a clean scan is not proof of security. Confirm each one by hand using its ` +
		`"reproduction" steps, then dig deeper with manual testing before you report anything. Only test what you are ` +
		`authorized to test.</p></div></section>`)

	// ---- References ----
	b.WriteString(`<section id="refs" class="block"><div class="block-num">08</div><h2>References</h2><ul class="refs">`)
	for _, r := range [][2]string{
		{"OWASP Top 10 2025 — A01 Broken Access Control", "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/"},
		{"PortSwigger — Access control vulnerabilities", "https://portswigger.net/web-security/access-control"},
		{"PortSwigger — IDOR", "https://portswigger.net/web-security/access-control/idor"},
		{"OWASP Web Security Testing Guide — Authorization", "https://owasp.org/www-project-web-security-testing-guide/"},
		{"CWE-284 — Improper Access Control", "https://cwe.mitre.org/data/definitions/284.html"},
		{"CWE-639 — Authorization Bypass Through User-Controlled Key", "https://cwe.mitre.org/data/definitions/639.html"},
	} {
		b.WriteString(`<li><a href="` + esc(r[1]) + `">` + esc(r[0]) + `</a></li>`)
	}
	b.WriteString(`</ul></section>`)

	b.WriteString(`</main>`)
	b.WriteString(`<footer><div class="foot-in"><span>Breakero — generated for authorized security testing</span>` +
		`<span class="mono">github.com/aljevon</span></div>` +
		`<div class="foot-note">Confidential — contains security-sensitive information. Handle and distribute on a need-to-know basis.</div></footer>`)
	b.WriteString(`<a class="totop" href="#top" title="Back to top">↑</a>`)
	// Minimal JS: close the contents dropdown after a jump.
	b.WriteString(`<script>document.querySelectorAll('.menu-panel a').forEach(function(a){a.addEventListener('click',function(){var d=document.querySelector('.menu');if(d)d.open=false;});});</script>`)
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

// titleCase returns s with only its first letter capitalized ("CRITICAL" -> "Critical").
func titleCase(s string) string {
	s = strings.ToLower(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

const reportCSS = `
:root{--bg:#0b0b0c;--panel:#101012;--panel2:#0d0d0f;--ink:#e8e8ea;--muted:#9a9aa2;--dim:#6a6a72;
--line:#232327;--line2:#2e2e34;--acc:#f2860a;--acc-soft:rgba(242,134,10,.12);
--mono:ui-monospace,"SFMono-Regular","JetBrains Mono",Menlo,Consolas,monospace;
--sans:"Inter","Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 var(--sans);
background-image:radial-gradient(120% 60% at 50% -10%,rgba(242,134,10,.05),transparent 60%)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.mono{font-family:var(--mono)}
h1,h2,h3{letter-spacing:.2px}
/* severity color tokens */
.sev-cell-critical,.risk-critical{--c:#f2860a}
.sev-cell-high,.risk-high{--c:#f2860a}
.sev-cell-medium,.risk-medium{--c:#cdd0d8}
.sev-cell-low,.risk-low{--c:#8a8a92}
.sev-cell-info,.risk-info{--c:#6a6a72}
.risk-none{--c:#4b8a52}

/* masthead */
.mast{position:sticky;top:0;z-index:40;background:rgba(11,11,12,.86);backdrop-filter:blur(8px);
border-bottom:1px solid var(--line)}
.mast-in{max-width:940px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;gap:14px}
.brand{font-family:var(--mono);font-weight:700;font-size:14px;letter-spacing:.3px;display:flex;align-items:center;gap:8px}
.brand .mark{color:var(--acc)}
.brand-sub{color:var(--dim);font-weight:400;font-size:11px;text-transform:uppercase;letter-spacing:1.5px;padding-left:2px}
.mast-tools{margin-left:auto;display:flex;align-items:center;gap:12px}
.classif{font-family:var(--mono);font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--acc);
border:1px solid var(--acc);border-radius:3px;padding:3px 8px}
/* contents dropdown */
.menu{position:relative}
.menu summary{list-style:none;cursor:pointer;font-family:var(--mono);font-size:12px;color:var(--ink);
border:1px solid var(--line2);border-radius:4px;padding:6px 12px;user-select:none}
.menu summary::-webkit-details-marker{display:none}
.menu summary::after{content:" ▾";color:var(--muted)}
.menu[open] summary{border-color:var(--acc);color:var(--acc)}
.menu-panel{position:absolute;right:0;top:calc(100% + 8px);width:340px;max-width:78vw;max-height:70vh;overflow:auto;
background:var(--panel);border:1px solid var(--line2);border-radius:6px;padding:6px;
box-shadow:0 18px 40px rgba(0,0,0,.5)}
.menu-panel a{display:block;padding:7px 10px;border-radius:4px;color:var(--ink);font-size:13px}
.menu-panel a:hover{background:var(--acc-soft);text-decoration:none}
.menu-group{font-family:var(--mono);font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--dim);
padding:10px 10px 4px;border-top:1px solid var(--line);margin-top:4px}
.menu-f{display:flex!important;align-items:baseline;gap:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.menu-f .mfid{font-family:var(--mono);font-size:11px;color:var(--muted);flex:0 0 auto}
.menu-f .mftitle{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mdot{width:7px;height:7px;border-radius:50%;flex:0 0 auto;background:var(--c,#6a6a72)}

main{max-width:940px;margin:0 auto;padding:0 20px 40px}
section{scroll-margin-top:70px}

/* cover */
.cover{padding:44px 0 30px;border-bottom:1px solid var(--line)}
.doctype{font-family:var(--mono);font-size:11px;letter-spacing:3px;text-transform:uppercase;color:var(--acc);margin-bottom:12px}
.cover h1{margin:0;font-size:38px;line-height:1.12;font-weight:800}
.cover .std{color:var(--muted);margin:8px 0 26px;font-size:14px}
.cover-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:var(--line);
border:1px solid var(--line);border-radius:6px;overflow:hidden}
.cg{background:var(--panel);padding:13px 16px;display:flex;flex-direction:column;gap:3px}
.cg-k{font-family:var(--mono);font-size:10px;letter-spacing:1.2px;text-transform:uppercase;color:var(--dim)}
.cg-v{font-size:14px;color:var(--ink);word-break:break-word}
.cg-risk{background:linear-gradient(180deg,var(--acc-soft),transparent)}
.cg-risk .cg-v{color:var(--c);font-weight:700}
.cg-risk.risk-none .cg-v{color:var(--c)}

/* blocks */
.block{position:relative;padding:34px 0 6px;border-bottom:1px solid var(--line)}
.block:last-of-type{border-bottom:0}
.block-num{position:absolute;top:30px;right:0;font-family:var(--mono);font-size:12px;color:var(--dim);letter-spacing:2px}
.block h2{margin:0 0 14px;font-size:22px;font-weight:700;padding-bottom:10px;border-bottom:2px solid var(--acc);display:inline-block}
.lead{font-size:15.5px;line-height:1.7;color:#d6d6db;max-width:70ch}
.muted{color:var(--muted);font-size:13.5px}
.block p{max-width:74ch}

/* risk banner */
.riskbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:2px 0 18px;
border:1px solid var(--line2);border-left:4px solid var(--c);border-radius:5px;padding:12px 16px;background:var(--panel)}
.riskbar-k{font-family:var(--mono);font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted)}
.riskbar-v{font-size:16px;font-weight:800;color:var(--c);text-transform:uppercase;letter-spacing:.5px}

/* stat grid */
.statgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0 6px}
.stat{background:var(--panel);border:1px solid var(--line);border-top:2px solid var(--c);border-radius:5px;
padding:14px 12px;text-align:center}
.stat-n{display:block;font-family:var(--mono);font-size:26px;font-weight:700;color:var(--c);line-height:1}
.stat-l{display:block;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-top:6px}

/* distribution */
.dist{display:flex;flex-direction:column;gap:9px;margin:16px 0 8px}
.dist-row{display:flex;align-items:center;gap:12px}
.dist-l{width:110px;font-size:12.5px;color:var(--muted)}
.dist-track{flex:1;height:12px;background:var(--panel);border:1px solid var(--line);border-radius:3px;overflow:hidden}
.dist-bar{display:block;height:100%;background:var(--c);min-width:2px}
.dist-n{width:26px;text-align:right;font-family:var(--mono);font-size:13px;color:var(--ink)}

/* badges */
.badge{display:inline-block;font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:1px;
padding:3px 9px;border-radius:3px;border:1px solid var(--line2);color:var(--ink)}
.badge.sev-critical{background:var(--acc);border-color:var(--acc);color:#0b0b0c}
.badge.sev-high{background:transparent;border-color:var(--acc);color:var(--acc)}
.badge.sev-medium{color:#cdd0d8}
.badge.sev-low{color:#8a8a92}
.badge.sev-info{color:#6a6a72}

/* index table */
.idx,.cov{width:100%;border-collapse:collapse;margin-top:6px;font-size:13.5px}
.idx thead th,.cov thead th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:1px;text-transform:uppercase;
color:var(--dim);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line2)}
.idx td,.cov td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
.idx tbody tr{cursor:pointer}
.idx tbody tr:hover{background:var(--acc-soft)}
.idx .ep,.cov .mono{color:var(--muted)}
.ep{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.res-hit{color:var(--acc)}.res-err{color:#e0705a}.res-ok{color:var(--dim)}

/* finding cards */
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:6px;
padding:20px 22px;margin:16px 0}
.sev-edge-critical{--c:#f2860a}.sev-edge-high{--c:#f2860a}.sev-edge-medium{--c:#cdd0d8}
.sev-edge-low{--c:#8a8a92}.sev-edge-info{--c:#6a6a72}
.fhead{display:flex;align-items:center;gap:12px}
.fhead-l{display:flex;align-items:center;gap:10px}
.fid{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--muted);letter-spacing:1px}
.fhead-top{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--dim)}
.finding h3{margin:12px 0 14px;font-size:19px;font-weight:700}
.meta-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:var(--line);
border:1px solid var(--line);border-radius:5px;overflow:hidden;margin-bottom:16px}
.mg{background:var(--panel2);padding:10px 13px;display:flex;flex-direction:column;gap:3px;min-width:0}
.mg-k{font-family:var(--mono);font-size:9.5px;letter-spacing:1.2px;text-transform:uppercase;color:var(--dim)}
.mg-v{font-size:13.5px;color:var(--ink);word-break:break-word}
.field{margin:14px 0}
.flabel{display:block;font-family:var(--mono);text-transform:uppercase;font-size:10.5px;letter-spacing:1.2px;
color:var(--acc);font-weight:700;margin-bottom:5px}
.field p{margin:0;color:#d3d3d9;max-width:78ch}
.repro{white-space:pre-wrap;word-break:break-word;background:var(--panel2);border:1px solid var(--line2);border-radius:5px;
padding:12px 14px;margin:0;font-family:var(--mono);font-size:12.5px;line-height:1.6;color:#c9cdd8}
.ref{color:var(--muted);font-size:12.5px;margin-top:16px;padding-top:12px;border-top:1px solid var(--line)}

/* clean state */
.clean{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:24px}
.clean h3{margin:0 0 8px;font-size:18px}

/* methodology + callout */
.sevkey ul,.callout p,.refs{margin:0}
.sevkey{margin-top:16px}
.sevkey ul{padding-left:18px;color:#d3d3d9}.sevkey li{margin:6px 0}
.callout{background:var(--acc-soft);border:1px solid var(--acc);border-radius:6px;padding:16px 18px}
.callout p{color:#ecdcc6;max-width:none}
.refs{list-style:none;padding:0}
.refs li{padding:9px 0;border-bottom:1px solid var(--line)}
.refs li:last-child{border-bottom:0}

/* footer + to-top */
footer{max-width:940px;margin:0 auto;padding:26px 20px 60px;color:var(--muted)}
.foot-in{display:flex;justify-content:space-between;gap:16px;font-size:12.5px;flex-wrap:wrap;
padding-top:20px;border-top:1px solid var(--line)}
.foot-note{margin-top:10px;font-size:11px;color:var(--dim);letter-spacing:.3px}
.totop{position:fixed;right:18px;bottom:18px;z-index:30;width:40px;height:40px;border-radius:50%;
background:var(--acc);color:#0b0b0c;display:flex;align-items:center;justify-content:center;font-size:18px;
font-weight:700;box-shadow:0 6px 18px rgba(0,0,0,.4)}
.totop:hover{text-decoration:none;filter:brightness(1.1)}

@media (max-width:640px){
.cover-grid,.meta-grid{grid-template-columns:1fr}
.statgrid{grid-template-columns:repeat(2,1fr)}
.cover h1{font-size:30px}
.menu-panel{width:78vw}
.block-num{display:none}
.ep{max-width:150px}
}
@media print{
.mast,.totop{display:none}
body{background:#fff;color:#111}
.finding,.stat,.cg,.mg,.callout,.clean{background:#fff}
a{color:#000}
}
`

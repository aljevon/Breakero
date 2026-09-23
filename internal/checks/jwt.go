package checks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/finding"
)

// JWTCheck inspects any JSON Web Tokens found in the configured role
// credentials (cookies or Authorization headers). OWASP A01 includes
// "metadata manipulation" such as tampering with a JWT to elevate privileges.
//
// This check is passive and local: it decodes tokens you already hold and
// reports weaknesses that would make tampering easy (for example alg=none, a
// missing expiry, or a role/admin claim carried client-side). It does NOT
// forge tokens or replay modified tokens against the server, so it is safe to
// run and cannot alter the target.
type JWTCheck struct{}

func (JWTCheck) ID() string    { return "jwt-inspect" }
func (JWTCheck) Title() string { return "Token / JWT weakness inspection (metadata manipulation)" }
func (JWTCheck) Teaches() string {
	return "Many apps store your identity and role inside a token (a JWT) that the " +
		"browser sends back. If that token is not properly signed and checked, an " +
		"attacker can edit it to say 'role: admin'. This test decodes the tokens you " +
		"provided and points out weaknesses that make such tampering possible."
}

var jwtRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

func (c *JWTCheck) Run(ctx *Context) ([]finding.Finding, error) {
	cfg := ctx.Config
	var out []finding.Finding
	seen := map[string]bool{}

	for _, r := range cfg.Roles {
		for _, tok := range extractTokens(r) {
			if seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, inspectJWT(c.ID(), c.Teaches(), roleLabel(r), tok)...)
		}
	}
	if len(cfg.Roles) == 0 {
		ctx.Log.Printf("[jwt-inspect] skipped: no roles with credentials configured")
	}
	return out, nil
}

func extractTokens(r config.Role) []string {
	var toks []string
	sources := []string{r.Cookie}
	for _, v := range r.Headers {
		sources = append(sources, v)
	}
	for _, s := range sources {
		toks = append(toks, jwtRE.FindAllString(s, -1)...)
	}
	return toks
}

func inspectJWT(id, teaches, role, tok string) []finding.Finding {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	header := decodeSegment(parts[0])
	payload := decodeSegment(parts[1])

	var hdr map[string]any
	var pl map[string]any
	_ = json.Unmarshal(header, &hdr)
	_ = json.Unmarshal(payload, &pl)

	shortTok := truncate(tok, 24)
	var out []finding.Finding

	// alg=none is critical: the server may accept an unsigned token.
	if alg, _ := hdr["alg"].(string); strings.EqualFold(alg, "none") {
		out = append(out, finding.New(id,
			fmt.Sprintf("JWT for role %q uses alg=none (unsigned)", role), finding.Critical).
			WithMeaning(teaches).
			WithEvidence(fmt.Sprintf("Token %s header declares \"alg\":\"none\". An unsigned token can be "+
				"edited freely.", shortTok)).
			WithConfidence("confirmed").
			WithRemediation("Reject tokens with alg=none. Pin the expected algorithm server-side and verify "+
				"the signature with a strong key before trusting any claim."))
	}

	// Missing expiry.
	if _, ok := pl["exp"]; !ok {
		out = append(out, finding.New(id,
			fmt.Sprintf("JWT for role %q has no expiry (exp) claim", role), finding.Medium).
			WithMeaning(teaches).
			WithEvidence(fmt.Sprintf("Token %s payload has no \"exp\" claim; a stolen token would be valid "+
				"indefinitely.", shortTok)).
			WithConfidence("confirmed").
			WithRemediation("Always set a short exp on tokens and reject expired ones. Consider rotation and "+
				"server-side revocation for sensitive sessions."))
	} else if expF, ok := pl["exp"].(float64); ok {
		if time.Unix(int64(expF), 0).Before(time.Now()) {
			out = append(out, finding.New(id,
				fmt.Sprintf("JWT for role %q is already expired", role), finding.Info).
				WithMeaning(teaches).
				WithEvidence(fmt.Sprintf("Token %s expired at %s; results using it may be unreliable.",
					shortTok, time.Unix(int64(expF), 0).UTC().Format(time.RFC3339))).
				WithConfidence("confirmed").
				WithRemediation("Refresh the token before scanning so authenticated checks are accurate."))
		}
	}

	// Privilege-bearing claims carried client-side.
	for _, claim := range []string{"role", "roles", "admin", "is_admin", "isAdmin", "scope", "authorities", "groups"} {
		if v, ok := pl[claim]; ok {
			out = append(out, finding.New(id,
				fmt.Sprintf("JWT for role %q carries a privilege claim %q", role, claim), finding.Low).
				WithMeaning(teaches).
				WithEvidence(fmt.Sprintf("Token %s payload contains %q=%v. If the signature is weak or "+
					"unchecked, this is the value an attacker would tamper with to escalate.",
					shortTok, claim, v)).
				WithConfidence("needs-review").
				WithRemediation("Ensure the token signature is strong and always verified. Do not make trust "+
					"decisions from a client-held claim without server-side validation; re-check authorization "+
					"against a trusted store for sensitive actions."))
			break
		}
	}
	return out
}

func decodeSegment(seg string) []byte {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b
	}
	if b, err := base64.URLEncoding.DecodeString(seg); err == nil {
		return b
	}
	return nil
}

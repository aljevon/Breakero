package checks

import (
	"fmt"
	"math"
	"strings"

	"github.com/aljevon/breakero/internal/config"
	"github.com/aljevon/breakero/internal/httpx"
)

// roleLabel returns a friendly label for a role, treating level 0 as anonymous.
func roleLabel(r config.Role) string {
	if r.Name != "" {
		return r.Name
	}
	if r.Level == 0 {
		return "anonymous"
	}
	return fmt.Sprintf("role-L%d", r.Level)
}

// asRole returns the request headers and cookie for sending as a given role.
func asRole(r config.Role) (map[string]string, string) {
	return r.Headers, r.Cookie
}

// isGrantedContent reports whether a response looks like the server actually
// served protected content, as opposed to a login wall or an access-denied
// page. This is the core heuristic that separates "I got in" from "I was
// stopped".
func isGrantedContent(resp *httpx.Response) bool {
	if resp == nil {
		return false
	}
	if resp.Status < 200 || resp.Status >= 400 {
		return false
	}
	if resp.LooksAuthenticatedGate() {
		return false
	}
	// A 200 with an almost-empty body is rarely meaningful protected content.
	if resp.Status == 200 && resp.BodyLen < 8 {
		return false
	}
	return true
}

// BodySimilarity is an exported wrapper around similarity so other packages
// (such as the engine's calibration step) can compare two response bodies.
func BodySimilarity(a, b []byte) float64 { return similarity(a, b) }

// similarity returns a rough 0..1 similarity score between two response
// bodies based on length and a shingle overlap. It is used to decide whether
// two roles received "the same" page.
func similarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	la, lb := float64(len(a)), float64(len(b))
	lenRatio := math.Min(la, lb) / math.Max(la, lb)

	setA := shingles(a)
	setB := shingles(b)
	if len(setA) == 0 || len(setB) == 0 {
		return lenRatio
	}
	inter := 0
	for s := range setA {
		if setB[s] {
			inter++
		}
	}
	union := len(setA) + len(setB) - inter
	jaccard := float64(inter) / float64(union)
	// Blend length ratio and content overlap.
	return 0.4*lenRatio + 0.6*jaccard
}

func shingles(b []byte) map[uint64]bool {
	const k = 8
	if len(b) < k {
		return map[uint64]bool{hash64(b): true}
	}
	set := make(map[uint64]bool)
	for i := 0; i+k <= len(b); i += 4 { // step to keep the set small
		set[hash64(b[i:i+k])] = true
	}
	return set
}

func hash64(b []byte) uint64 {
	var h uint64 = 1469598103934665603
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// truncate shortens s for use in evidence strings.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// evidenceForResponse builds a short evidence line from a response.
func evidenceForResponse(resp *httpx.Response) string {
	if resp == nil {
		return "no response"
	}
	ct := resp.Header.Get("Content-Type")
	return fmt.Sprintf("HTTP %d, %d bytes, content-type=%q", resp.Status, resp.BodyLen, truncate(ct, 60))
}

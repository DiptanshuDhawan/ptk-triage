// Package orchestrator turns ptk from a pure file-triage tool into one that can
// also *run* the upstream recon tools (subfinder, nmap, ffuf), collect their
// native output into an engagement folder, and then hand that folder to the
// existing parser -> rule-engine -> report pipeline unchanged.
//
// Design principles:
//
//   - Shell out to the real tools rather than reimplement them. nmap's service
//     fingerprints and ffuf's fuzzing engine are not worth rebuilding; we just
//     drive them and point their output flags at files we then parse.
//   - Degrade gracefully, never crash. A missing tool is a skipped stage with a
//     warning, exactly like a truncated input file is a warning elsewhere.
//   - Keep the risky/impure bits (process execution, DNS, HTTP) behind small
//     interfaces so the planning/command-building logic is unit-testable
//     without the tools installed or a live network.
//   - File-based artifacts. Everything a run produces lands in the output
//     folder in the same formats the parsers already read, so `triage all` and
//     `triage diff` work on a scan's output for free.
//
// This file: classifying what the user pointed us at (domain / IP / CIDR),
// which decides whether subdomain enumeration even applies.
package orchestrator

import (
	"net"
	"strings"
)

// TargetKind is what the user's target string represents.
type TargetKind int

const (
	KindUnknown TargetKind = iota
	KindDomain             // a hostname/FQDN, e.g. target.com — subdomain enum applies
	KindIP                 // a single IP literal, e.g. 10.10.10.5
	KindCIDR               // a network range, e.g. 10.10.10.0/24
)

func (k TargetKind) String() string {
	switch k {
	case KindDomain:
		return "domain"
	case KindIP:
		return "ip"
	case KindCIDR:
		return "cidr"
	default:
		return "unknown"
	}
}

// Target is a classified scan target.
type Target struct {
	Raw  string // normalized form (scheme/path/trailing dot stripped, lowercased for domains)
	Kind TargetKind
}

// ClassifyTarget normalizes and classifies a raw target string. It tolerates a
// pasted URL (http://host/path -> host), a trailing dot on an FQDN, and
// surrounding whitespace. Order matters: CIDR and IP literals are checked
// before the domain heuristic so "10.0.0.0/24" is never mistaken for a
// hostname.
func ClassifyTarget(raw string) Target {
	s := strings.TrimSpace(raw)

	// Strip a scheme and anything after the authority if a URL was pasted.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		// Keep CIDR slashes: only strip a path slash if what precedes it is not
		// an IP network. We detect that by trying ParseCIDR on the whole first.
		if _, _, err := net.ParseCIDR(s); err != nil {
			s = s[:i]
		}
	}
	// Strip a port suffix on host:port (but not on an IPv6 literal or CIDR).
	s = stripPort(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSpace(s)

	if s == "" {
		return Target{Raw: raw, Kind: KindUnknown}
	}

	if _, _, err := net.ParseCIDR(s); err == nil {
		return Target{Raw: s, Kind: KindCIDR}
	}
	if ip := net.ParseIP(s); ip != nil {
		return Target{Raw: s, Kind: KindIP}
	}
	if looksLikeHostname(s) {
		return Target{Raw: strings.ToLower(s), Kind: KindDomain}
	}
	return Target{Raw: s, Kind: KindUnknown}
}

// stripPort removes a trailing :NNNN port from host:port, leaving IPv6 literals
// and CIDRs alone.
func stripPort(s string) string {
	if strings.Contains(s, "/") { // CIDR — never has a port
		return s
	}
	if strings.Count(s, ":") != 1 { // 0 => no port; >1 => IPv6 literal
		return s
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	if host == "" {
		return s
	}
	// Only treat as a port if it's all digits.
	for _, r := range port {
		if r < '0' || r > '9' {
			return s
		}
	}
	return host
}

// looksLikeHostname reports whether s is a plausible DNS hostname: one or more
// labels separated by dots, with an alphabetic TLD of 2+ chars. A bare single
// label (no dot) is rejected to avoid treating typos as targets.
func looksLikeHostname(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	for i, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_'
			if !ok {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		// The TLD (last label) must be alphabetic so "1.2.3.4" (already handled
		// as IP, but as defense in depth) and "foo.123" don't pass.
		if i == len(labels)-1 {
			for _, r := range label {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
					return false
				}
			}
		}
	}
	return true
}

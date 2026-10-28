// Package rules is the engine that turns normalized model.Items into Findings.
//
// Design: the engine is data-driven. A RuleSet is loaded from YAML (either the
// embedded default or a user-supplied file) so the operator can tune and extend
// what gets flagged without recompiling. Two rule flavours exist:
//
//  1. Pattern rules — regex matched against a named field of an Item
//     (service, banner, path, name, scripts, ...). These cover the vast
//     majority of "flag X when it looks like Y" needs.
//
//  2. Built-in computed rules — logic that pure regex cannot express:
//     response-size outliers (ffuf baseline deviation), dangling CNAMEs,
//     resolved-but-no-web subdomains, non-standard port/service combos,
//     nmap-guessed (unprobed) services, and off-range subdomain IPs. These are
//     toggled and tuned from the same YAML file.
//
// Every Finding carries a human reason. The engine refuses to emit a finding
// without one — a flag you cannot explain is noise.
package rules

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"ptk/internal/model"
)

// PatternRule is a single YAML-defined regex rule.
type PatternRule struct {
	ID       string   `yaml:"id"`
	Field    string   `yaml:"field"`    // which Item field to match
	Pattern  string   `yaml:"pattern"`  // regex (case-insensitive by default)
	Severity string   `yaml:"severity"` // HIGH/MED/LOW/INFO
	Reason   string   `yaml:"reason"`   // human explanation; may use {match}/{target}
	Ports    []int    `yaml:"ports"`    // optional: only apply to these ports
	Kinds    []string `yaml:"kinds"`    // optional: restrict to host/path/sub

	re *regexp.Regexp
}

// Builtins toggles and tunes the computed rules.
type Builtins struct {
	// ffuf
	SizeOutlier       bool    `yaml:"size_outlier"`
	SizeOutlierPct    float64 `yaml:"size_outlier_pct"`     // deviation from baseline to flag
	SizeOutlierMinSet int     `yaml:"size_outlier_min_set"` // need at least N paths for a baseline
	InterestingStatus bool    `yaml:"interesting_status"`

	// nmap
	NonStandardHTTP bool  `yaml:"nonstandard_http"`
	StandardHTTP    []int `yaml:"standard_http_ports"`
	NonStandardSSH  bool  `yaml:"nonstandard_ssh"`
	StandardSSH     []int `yaml:"standard_ssh_ports"`
	GuessedService  bool  `yaml:"guessed_service"`
	UnknownService  bool  `yaml:"unknown_service"`

	// subs
	DanglingCNAME bool     `yaml:"dangling_cname"`
	ResolvedNoWeb bool     `yaml:"resolved_no_web"`
	OffRangeIP    bool     `yaml:"offrange_ip"`
	PrimaryCIDRs  []string `yaml:"primary_cidrs"` // org's main ranges; empty => infer

	// cross-signal confidence boost (stretch): combos that raise severity.
	Combos bool `yaml:"combos"`
}

// RuleSet is the full configuration loaded from YAML.
type RuleSet struct {
	Patterns []PatternRule `yaml:"patterns"`
	Builtins Builtins      `yaml:"builtins"`

	primaryNets []*net.IPNet
}

// compile prepares regexes and parses CIDRs. Invalid rules are reported but do
// not abort loading — one bad rule should not disable the whole set.
func (rs *RuleSet) compile() []string {
	var warns []string
	for i := range rs.Patterns {
		p := &rs.Patterns[i]
		if p.Pattern == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + p.Pattern)
		if err != nil {
			warns = append(warns, fmt.Sprintf("rule %q: bad pattern %q: %v", p.ID, p.Pattern, err))
			continue
		}
		p.re = re
	}
	for _, c := range rs.Builtins.PrimaryCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			rs.primaryNets = append(rs.primaryNets, n)
		} else {
			warns = append(warns, fmt.Sprintf("primary_cidrs: bad CIDR %q: %v", c, err))
		}
	}
	return warns
}

// fieldValue extracts the named matchable field from an Item.
func fieldValue(it model.Item, field string) string {
	switch strings.ToLower(field) {
	case "service":
		return it.Service
	case "product":
		return it.Product
	case "version":
		return it.Version
	case "banner":
		return it.Banner
	case "scripts":
		return it.Scripts
	case "path":
		return it.Path
	case "url":
		return it.URL
	case "name":
		return it.Name
	case "cname":
		return it.CNAME
	case "redirect":
		return it.Redir
	default:
		return ""
	}
}

func kindAllowed(kinds []string, k model.Kind) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, s := range kinds {
		if strings.EqualFold(s, string(k)) {
			return true
		}
	}
	return false
}

func portAllowed(ports []int, port int) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// Evaluate runs the full ruleset over items and returns sorted findings.
func (rs *RuleSet) Evaluate(items []model.Item) []model.Finding {
	var findings []model.Finding

	// Pattern rules.
	for _, it := range items {
		for _, p := range rs.Patterns {
			if p.re == nil {
				continue
			}
			if !kindAllowed(p.Kinds, it.Kind) {
				continue
			}
			if it.Kind == model.KindHost && !portAllowed(p.Ports, it.Port) {
				continue
			}
			val := fieldValue(it, p.Field)
			if val == "" {
				continue
			}
			if m := p.re.FindString(val); m != "" {
				findings = append(findings, newFinding(it, model.ParseSeverity(p.Severity), p.ID,
					expand(p.Reason, m, it)))
			}
		}
	}

	// Built-in computed rules.
	findings = append(findings, rs.builtinFindings(items)...)

	// Cross-signal confidence boosts.
	if rs.Builtins.Combos {
		applyCombos(findings)
	}

	findings = dedupe(findings)
	model.SortFindings(findings)
	return findings
}

func (rs *RuleSet) builtinFindings(items []model.Item) []model.Finding {
	var out []model.Finding

	// ffuf baseline for size-outlier detection.
	var pathItems []model.Item
	for _, it := range items {
		if it.Kind == model.KindPath {
			pathItems = append(pathItems, it)
		}
	}
	baseLen, baseCount := modalLength(pathItems)

	for _, it := range items {
		switch it.Kind {
		case model.KindHost:
			out = append(out, rs.hostBuiltins(it)...)
		case model.KindPath:
			out = append(out, rs.pathBuiltins(it, baseLen, baseCount, len(pathItems))...)
		case model.KindSub:
			out = append(out, rs.subBuiltins(it)...)
		}
	}
	return out
}

func (rs *RuleSet) hostBuiltins(it model.Item) []model.Finding {
	var out []model.Finding
	b := rs.Builtins
	svc := strings.ToLower(it.Service)

	if b.NonStandardHTTP && isHTTPService(it) && !containsInt(b.StandardHTTP, it.Port) {
		out = append(out, newFinding(it, model.SevMedium, "nonstandard-http",
			fmt.Sprintf("HTTP service on non-standard port %d — worth manual inspection", it.Port)))
	}
	if b.NonStandardSSH && svc == "ssh" && !containsInt(b.StandardSSH, it.Port) {
		out = append(out, newFinding(it, model.SevLow, "nonstandard-ssh",
			fmt.Sprintf("SSH on non-standard port %d — possible deliberate relocation", it.Port)))
	}
	if b.GuessedService && it.Extra["service_guessed"] == "true" {
		out = append(out, newFinding(it, model.SevLow, "guessed-service",
			fmt.Sprintf("Port %d open but service only guessed from port number (not probed) — confirm manually", it.Port)))
	}
	if b.UnknownService && (svc == "" || svc == "unknown" || svc == "tcpwrapped") {
		out = append(out, newFinding(it, model.SevMedium, "unknown-service",
			fmt.Sprintf("Open port %d with unidentified service — enumerate manually", it.Port)))
	}
	return out
}

func (rs *RuleSet) pathBuiltins(it model.Item, baseLen, baseCount, setSize int) []model.Finding {
	var out []model.Finding
	b := rs.Builtins

	if b.InterestingStatus {
		switch {
		case it.Status == 403:
			out = append(out, newFinding(it, model.SevMedium, "status-403",
				"403 Forbidden — resource exists but is access-controlled; try bypass techniques"))
		case it.Status == 401:
			out = append(out, newFinding(it, model.SevMedium, "status-401",
				"401 Unauthorized — authenticated resource present; check for weak/default creds"))
		case it.Status >= 500 && it.Status < 600:
			out = append(out, newFinding(it, model.SevMedium, "status-5xx",
				fmt.Sprintf("%d server error — may leak stack traces or indicate injectable endpoint", it.Status)))
		case it.Status >= 301 && it.Status <= 308:
			reason := fmt.Sprintf("%d redirect", it.Status)
			if it.Redir != "" {
				reason += " -> " + it.Redir
			}
			reason += " — follow to find the real resource"
			out = append(out, newFinding(it, model.SevLow, "status-redirect", reason))
		}
	}

	if b.SizeOutlier && setSize >= max(b.SizeOutlierMinSet, 1) && baseCount > 0 {
		// Flag entries whose length deviates from the modal baseline by more
		// than the configured percentage. These are the needles in the 404 pile.
		dev := pctDiff(it.Length, baseLen)
		pct := b.SizeOutlierPct
		if pct <= 0 {
			pct = 0.25
		}
		if it.Length != baseLen && dev >= pct {
			out = append(out, newFinding(it, model.SevMedium, "size-outlier",
				fmt.Sprintf("Response size %dB deviates %.0f%% from baseline %dB (status %d) — likely a real find",
					it.Length, dev*100, baseLen, it.Status)))
		}
	}
	return out
}

func (rs *RuleSet) subBuiltins(it model.Item) []model.Finding {
	var out []model.Finding
	b := rs.Builtins

	if b.DanglingCNAME && (it.Dangling || (it.CNAME != "" && !it.Resolved)) {
		out = append(out, newFinding(it, model.SevHigh, "dangling-cname",
			fmt.Sprintf("Dangling CNAME -> %s (does not resolve) — possible subdomain takeover", it.CNAME)))
	}
	if b.ResolvedNoWeb && it.Resolved && !it.HTTPUp && it.CNAME == "" {
		out = append(out, newFinding(it, model.SevLow, "resolved-no-web",
			fmt.Sprintf("Resolves to %s but no web service seen — run a port scan", it.Address)))
	}
	if b.OffRangeIP && it.Resolved && rs.isOffRange(it.Address) {
		out = append(out, newFinding(it, model.SevLow, "offrange-ip",
			fmt.Sprintf("Resolves to %s, outside the primary IP range(s) — possibly different infra/hosting", it.Address)))
	}
	return out
}

// isOffRange reports whether an IP falls outside every configured primary CIDR.
// If no primary CIDRs are configured, it cannot judge and returns false.
func (rs *RuleSet) isOffRange(addr string) bool {
	if len(rs.primaryNets) == 0 {
		return false
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range rs.primaryNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// --- helpers ---------------------------------------------------------------

func newFinding(it model.Item, sev model.Severity, ruleID, reason string) model.Finding {
	return model.Finding{
		Item:     it,
		Kind:     it.Kind,
		Target:   it.Target(),
		Severity: sev,
		SevLabel: sev.String(),
		RuleID:   ruleID,
		Reason:   reason,
	}
}

// expand fills {match} and {target} placeholders in a reason string.
func expand(reason, match string, it model.Item) string {
	reason = strings.ReplaceAll(reason, "{match}", match)
	reason = strings.ReplaceAll(reason, "{target}", it.Target())
	return reason
}

func isHTTPService(it model.Item) bool {
	s := strings.ToLower(it.Service)
	prod := strings.ToLower(it.Product)
	// Explicitly exclude non-web services whose names/products merely contain
	// "http": RPC-over-HTTP (ncacn_http, 593) and the Windows HTTPAPI stack
	// that backs WinRM/WSMan (5985/47001) — those are not browseable web ports.
	if strings.Contains(s, "ncacn") || strings.Contains(s, "rpc") || strings.Contains(s, "soap") {
		return false
	}
	if strings.Contains(prod, "rpc") || strings.Contains(prod, "httpapi") {
		return false
	}
	switch s {
	case "http", "https", "http-alt", "http-proxy", "https-alt", "http-mgmt", "ssl/http":
		return true
	}
	return strings.Contains(prod, "http")
}

func modalLength(items []model.Item) (length, count int) {
	freq := map[int]int{}
	for _, it := range items {
		freq[it.Length]++
	}
	for l, c := range freq {
		if c > count || (c == count && l < length) {
			length, count = l, c
		}
	}
	return
}

func pctDiff(a, base int) float64 {
	if base == 0 {
		if a == 0 {
			return 0
		}
		return 1
	}
	d := float64(a-base) / float64(base)
	if d < 0 {
		d = -d
	}
	return d
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// dedupe removes findings that share the same target + ruleID, keeping the
// highest severity instance.
func dedupe(fs []model.Finding) []model.Finding {
	best := map[string]int{}
	var out []model.Finding
	for _, f := range fs {
		k := f.Target + "|" + f.RuleID
		if idx, ok := best[k]; ok {
			if f.Severity > out[idx].Severity {
				out[idx] = f
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f)
	}
	return out
}

// applyCombos raises severity when independent signals reinforce each other on
// the same target. Example: an aging SMB banner AND port 445 open together are
// more actionable than either alone. This is intentionally conservative — it
// only promotes, never demotes, and only by one level.
func applyCombos(fs []model.Finding) {
	byTarget := map[string][]int{}
	for i, f := range fs {
		byTarget[f.Target] = append(byTarget[f.Target], i)
	}
	for _, idxs := range byTarget {
		if len(idxs) < 2 {
			continue
		}
		ruleSet := map[string]bool{}
		for _, i := range idxs {
			ruleSet[fs[i].RuleID] = true
		}
		// SMB + outdated-version style: a high-value service rule plus any
		// version/age rule on the same host.
		hasService := ruleSet["smb"] || ruleSet["rdp"] || ruleSet["winrm"] ||
			ruleSet["ldap"] || ruleSet["high-value-service"]
		hasAge := ruleSet["outdated-version"] || ruleSet["old-version"]
		if hasService && hasAge {
			for _, i := range idxs {
				if fs[i].Severity < model.SevHigh {
					fs[i].Severity++
					fs[i].SevLabel = fs[i].Severity.String()
					fs[i].Reason += " [boosted: multiple reinforcing signals on this target]"
				}
			}
		}
	}
}

// Filter returns only findings at or above the given minimum severity.
func Filter(fs []model.Finding, min model.Severity) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	return out
}

// Summary counts findings per severity for a report header.
func Summary(fs []model.Finding) map[string]int {
	m := map[string]int{"HIGH": 0, "MED": 0, "LOW": 0, "INFO": 0}
	for _, f := range fs {
		m[f.Severity.String()]++
	}
	return m
}

// SortedRuleIDs returns the distinct rule IDs present, sorted — handy for
// debugging which rules fired.
func SortedRuleIDs(fs []model.Finding) []string {
	set := map[string]bool{}
	for _, f := range fs {
		set[f.RuleID] = true
	}
	var ids []string
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

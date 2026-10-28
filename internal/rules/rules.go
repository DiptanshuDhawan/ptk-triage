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
//     response-size outliers (ffuf baseline deviation, computed per status
//     code), response-shape outliers (words/lines deviation when size alone
//     doesn't stand out), dangling CNAMEs, wildcard-DNS detection, resolved-
//     but-no-web subdomains, non-standard port/service combos, nmap-guessed
//     (unprobed) services, and off-range subdomain IPs. These are toggled and
//     tuned from the same YAML file.
//
// Every Finding carries a human reason. The engine refuses to emit a finding
// without one — a flag you cannot explain is noise.
//
// Performance: pattern rules are bucketed by item Kind at compile time so
// evaluating an item only walks the subset of rules that could possibly apply
// to it, rather than every rule in the set. For large result sets (a big ffuf
// wordlist run can produce tens of thousands of path items) rule evaluation is
// also parallelized across CPU cores, since matching is independent per item
// and purely CPU-bound (regex). Both optimizations matter more as the default
// ruleset grows — iterating ~150 rules per item serially does not scale as
// gracefully as iterating the ~20-40 that are actually relevant.
package rules

import (
	"fmt"
	"net"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

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
	Tags     []string `yaml:"tags"`     // optional: classification for combo logic (e.g. "service", "aged")

	re *regexp.Regexp
}

// Builtins toggles and tunes the computed rules.
type Builtins struct {
	// ffuf
	SizeOutlier       bool    `yaml:"size_outlier"`
	SizeOutlierPct    float64 `yaml:"size_outlier_pct"`     // deviation from baseline to flag
	SizeOutlierMinSet int     `yaml:"size_outlier_min_set"` // need at least N paths (of that status) for a baseline
	InterestingStatus bool    `yaml:"interesting_status"`
	ShapeOutlier      bool    `yaml:"shape_outlier"`     // words/lines deviation when size alone looks normal
	ShapeOutlierPct   float64 `yaml:"shape_outlier_pct"` // deviation in word count to flag

	// nmap
	NonStandardHTTP bool  `yaml:"nonstandard_http"`
	StandardHTTP    []int `yaml:"standard_http_ports"`
	NonStandardSSH  bool  `yaml:"nonstandard_ssh"`
	StandardSSH     []int `yaml:"standard_ssh_ports"`
	GuessedService  bool  `yaml:"guessed_service"`
	UnknownService  bool  `yaml:"unknown_service"`

	// subs
	DanglingCNAME       bool     `yaml:"dangling_cname"`
	ResolvedNoWeb       bool     `yaml:"resolved_no_web"`
	OffRangeIP          bool     `yaml:"offrange_ip"`
	PrimaryCIDRs        []string `yaml:"primary_cidrs"` // org's main ranges; empty => infer
	WildcardDNS         bool     `yaml:"wildcard_dns"`
	WildcardMinCount    int      `yaml:"wildcard_min_count"`    // need >= N subs sharing one IP
	WildcardMinFraction float64  `yaml:"wildcard_min_fraction"` // ...and that IP must cover >= this fraction

	// cross-signal confidence boost: combos that raise severity.
	Combos bool `yaml:"combos"`
}

// RuleSet is the full configuration loaded from YAML.
type RuleSet struct {
	Patterns []PatternRule `yaml:"patterns"`
	Builtins Builtins      `yaml:"builtins"`

	primaryNets []*net.IPNet
	byKind      map[model.Kind][]*PatternRule // precomputed bucket, built in compile()
}

// compile prepares regexes, parses CIDRs, and buckets patterns by Kind so
// Evaluate never has to scan irrelevant rules. Invalid rules are reported but
// do not abort loading — one bad rule should not disable the whole set.
func (rs *RuleSet) compile() []string {
	var warns []string
	rs.byKind = map[model.Kind][]*PatternRule{
		model.KindHost: nil,
		model.KindPath: nil,
		model.KindSub:  nil,
	}
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

		if len(p.Kinds) == 0 {
			for k := range rs.byKind {
				rs.byKind[k] = append(rs.byKind[k], p)
			}
			continue
		}
		for _, ks := range p.Kinds {
			k := model.Kind(strings.ToLower(strings.TrimSpace(ks)))
			if _, ok := rs.byKind[k]; ok {
				rs.byKind[k] = append(rs.byKind[k], p)
			} else {
				warns = append(warns, fmt.Sprintf("rule %q: unknown kind %q (expected host/path/sub)", p.ID, ks))
			}
		}
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

// parallelThreshold is the item-count floor above which Evaluate splits work
// across goroutines. Below it, goroutine/channel overhead would outweigh the
// gain — most nmap/subdomain scans never cross this line, but large ffuf
// wordlist runs routinely do.
const parallelThreshold = 1500

// Evaluate runs the full ruleset over items and returns sorted findings.
func (rs *RuleSet) Evaluate(items []model.Item) []model.Finding {
	findings := rs.evaluatePatterns(items)
	findings = append(findings, rs.builtinFindings(items)...)

	if rs.Builtins.Combos {
		applyCombos(findings)
	}

	findings = dedupe(findings)
	model.SortFindings(findings)
	return findings
}

// evaluatePatterns runs only the regex pattern rules, choosing a sequential or
// worker-pool strategy based on input size. Results are reassembled in a fixed
// chunk order so output is identical regardless of goroutine scheduling.
func (rs *RuleSet) evaluatePatterns(items []model.Item) []model.Finding {
	if len(items) < parallelThreshold {
		return rs.evaluatePatternsRange(items)
	}

	workers := runtime.NumCPU()
	if workers < 2 {
		return rs.evaluatePatternsRange(items)
	}
	if workers > len(items) {
		workers = len(items)
	}

	chunkSize := (len(items) + workers - 1) / workers
	results := make([][]model.Finding, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if start >= len(items) {
			break
		}
		if end > len(items) {
			end = len(items)
		}
		wg.Add(1)
		go func(idx int, chunk []model.Item) {
			defer wg.Done()
			results[idx] = rs.evaluatePatternsRange(chunk)
		}(w, items[start:end])
	}
	wg.Wait()

	var out []model.Finding
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

// evaluatePatternsRange is the sequential inner loop shared by both the
// direct and worker-pool paths.
func (rs *RuleSet) evaluatePatternsRange(items []model.Item) []model.Finding {
	var out []model.Finding
	for _, it := range items {
		for _, p := range rs.byKind[it.Kind] {
			if it.Kind == model.KindHost && !portAllowed(p.Ports, it.Port) {
				continue
			}
			val := fieldValue(it, p.Field)
			if val == "" {
				continue
			}
			if m := p.re.FindString(val); m != "" {
				out = append(out, newFinding(it, model.ParseSeverity(p.Severity), p.ID,
					expand(p.Reason, m, it), p.Tags...))
			}
		}
	}
	return out
}

func (rs *RuleSet) builtinFindings(items []model.Item) []model.Finding {
	var out []model.Finding

	// ffuf: compute a baseline PER STATUS CODE rather than one global baseline.
	// Mixing statuses into a single baseline is a real accuracy problem: a
	// wordlist run commonly has one "noise floor" for 200s (e.g. a SPA shell)
	// and a completely different one for 403s/redirects, so comparing a 403's
	// size against the 200 baseline produces false outliers in both directions.
	baselines := statusBaselines(items)

	for _, it := range items {
		switch it.Kind {
		case model.KindHost:
			out = append(out, rs.hostBuiltins(it)...)
		case model.KindPath:
			out = append(out, rs.pathBuiltins(it, baselines[it.Status])...)
		case model.KindSub:
			out = append(out, rs.subBuiltins(it)...)
		}
	}
	if f := rs.wildcardFinding(items); f != nil {
		out = append(out, *f)
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

// statusBaseline is the "noise floor" computed for one HTTP status code.
type statusBaseline struct {
	length int // modal response length within this status group
	count  int // how many items share that modal length
	words  int // modal word count within this status group (for shape-outlier)
	total  int // total items in this status group
}

// statusBaselines buckets path items by status code and computes modal-length
// and modal-word-count baselines within each bucket independently, each in a
// single pass over that bucket's items.
func statusBaselines(items []model.Item) map[int]statusBaseline {
	byStatus := map[int][]model.Item{}
	for _, it := range items {
		if it.Kind == model.KindPath {
			byStatus[it.Status] = append(byStatus[it.Status], it)
		}
	}
	out := make(map[int]statusBaseline, len(byStatus))
	for status, group := range byStatus {
		l, c := modalLength(group)
		w, _ := modalWords(group)
		out[status] = statusBaseline{length: l, count: c, words: w, total: len(group)}
	}
	return out
}

func (rs *RuleSet) pathBuiltins(it model.Item, bl statusBaseline) []model.Finding {
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

	pct := b.SizeOutlierPct
	if pct <= 0 {
		pct = 0.25
	}
	minSet := max(b.SizeOutlierMinSet, 1)
	isSizeOutlier := false

	if b.SizeOutlier && bl.total >= minSet && bl.count > 0 {
		// Flag entries whose length deviates from the modal baseline FOR THIS
		// STATUS CODE by more than the configured percentage. These are the
		// needles in the pile of same-status noise.
		dev := pctDiff(it.Length, bl.length)
		if it.Length != bl.length && dev >= pct {
			isSizeOutlier = true
			out = append(out, newFinding(it, model.SevMedium, "size-outlier",
				fmt.Sprintf("Response size %dB deviates %.0f%% from the status-%d baseline %dB — likely a real find",
					it.Length, dev*100, it.Status, bl.length)))
		}
	}

	// Shape outlier: catches the complementary case — a response whose BYTE
	// SIZE looks normal (so size-outlier stays quiet) but whose WORD COUNT is
	// well off the baseline for its status group, e.g. a page padded/truncated
	// to a similar byte count but with materially different content structure.
	// Only meaningful when size-outlier did NOT already flag the same item.
	if b.ShapeOutlier && !isSizeOutlier && bl.total >= minSet && bl.count > 0 {
		shapePct := b.ShapeOutlierPct
		if shapePct <= 0 {
			shapePct = 0.4
		}
		if bl.words > 0 {
			wdev := pctDiff(it.Words, bl.words)
			if it.Words != bl.words && wdev >= shapePct {
				out = append(out, newFinding(it, model.SevLow, "shape-outlier",
					fmt.Sprintf("Word count %d deviates %.0f%% from the status-%d baseline (%d) despite a similar byte size — structurally different response, worth a look",
						it.Words, wdev*100, it.Status, bl.words)))
			}
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

// wildcardFinding detects likely wildcard DNS: many distinct subdomains all
// resolving to the exact same IP. This matters because wildcard DNS silently
// undermines every other per-subdomain signal in this package — a dangling
// CNAME or off-range IP finding is only trustworthy if the resolution itself
// means something. Rather than try to suppress other findings (risking
// hiding a real takeover that coincidentally shares the wildcard IP), this
// emits one explicit heads-up so the operator applies the right skepticism.
func (rs *RuleSet) wildcardFinding(items []model.Item) *model.Finding {
	if !rs.Builtins.WildcardDNS {
		return nil
	}
	var subItems []model.Item
	for _, it := range items {
		if it.Kind == model.KindSub && it.Resolved && it.Address != "" {
			subItems = append(subItems, it)
		}
	}
	if len(subItems) == 0 {
		return nil
	}
	freq := map[string]int{}
	for _, it := range subItems {
		freq[it.Address]++
	}
	var topIP string
	var topCount int
	for ip, c := range freq {
		if c > topCount || (c == topCount && ip < topIP) {
			topIP, topCount = ip, c
		}
	}

	minCount := rs.Builtins.WildcardMinCount
	if minCount <= 0 {
		minCount = 5
	}
	minFrac := rs.Builtins.WildcardMinFraction
	if minFrac <= 0 {
		minFrac = 0.4
	}
	frac := float64(topCount) / float64(len(subItems))
	if topCount < minCount || frac < minFrac {
		return nil
	}

	f := newFinding(model.Item{Kind: model.KindSub, Name: topIP}, model.SevInfo, "wildcard-dns",
		fmt.Sprintf("%d of %d resolved subdomains share IP %s — likely wildcard DNS; treat individual resolution results in this scan with caution and verify manually",
			topCount, len(subItems), topIP))
	return &f
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

func newFinding(it model.Item, sev model.Severity, ruleID, reason string, tags ...string) model.Finding {
	return model.Finding{
		Item:     it,
		Kind:     it.Kind,
		Target:   it.Target(),
		Severity: sev,
		SevLabel: sev.String(),
		RuleID:   ruleID,
		Reason:   reason,
		Tags:     tags,
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

// modalWords returns the most common word count across a set of path items
// and how many items share it, mirroring modalLength. Used to compute a
// per-status-group baseline for shape-outlier detection.
func modalWords(items []model.Item) (words, count int) {
	freq := map[int]int{}
	for _, it := range items {
		freq[it.Words]++
	}
	for w, c := range freq {
		if c > count || (c == count && w < words) {
			words, count = w, c
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
// the same target. This is driven by Finding.Tags rather than hardcoded rule
// IDs, so any current or future rule tagged "service"/"aged" participates
// automatically — tagging a new rule is enough, no engine change required.
// Example: a high-value-service rule (tag "service", e.g. SMB) plus an aged-
// banner rule (tag "aged") firing on the same host:port is more actionable
// than either alone. This is intentionally conservative — it only promotes,
// never demotes, and only by one level.
func applyCombos(fs []model.Finding) {
	byTarget := map[string][]int{}
	for i, f := range fs {
		byTarget[f.Target] = append(byTarget[f.Target], i)
	}
	for _, idxs := range byTarget {
		if len(idxs) < 2 {
			continue
		}
		hasService, hasAged := false, false
		for _, i := range idxs {
			if fs[i].HasTag("service") {
				hasService = true
			}
			if fs[i].HasTag("aged") {
				hasAged = true
			}
		}
		if hasService && hasAged {
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

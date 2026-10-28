// Package report renders Findings (and optionally the full parsed data) to the
// terminal, or to JSON for piping into other tools.
//
// The terminal format is tool-wise: findings are grouped into one section per
// source tool (nmap, ffuf, subdomains), and each section is presented in that
// tool's own idiom — nmap's HOST:PORT/SERVICE/VERSION service table, ffuf's
// STATUS/SIZE/WORDS columns, a resolver-style SUBDOMAIN/RESOLVES-TO/STATE list.
// On top of that native shape it layers the enumeration-script aesthetic
// (linPEAS/winPEAS-style): a solid-background severity "badge" on every row so
// the must-check items pop out of the wall of output, and an inline tree-
// connected "why this matters / what to check" note under each row. Within a
// section rows are ordered HIGH-first (findings arrive pre-sorted), so the
// first thing you read in each tool is its worst finding; the section banner is
// itself tinted by that worst severity. A top-of-report badge summary gives the
// HIGH/MED/LOW/INFO counts at a glance.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"ptk/internal/model"
)

// Options controls rendering.
type Options struct {
	JSON    bool // emit machine-readable JSON instead of terminal text
	Full    bool // also print the complete parsed dataset, not just findings
	NoColor bool // disable ANSI color (auto-set when stdout is not a TTY)
	Width   int  // terminal width for banners; 0 => DefaultWidth
}

// DefaultWidth is used when the output isn't a real terminal (piped/
// redirected) or its size can't be determined.
const DefaultWidth = 100

const (
	minWidth = 70
	maxWidth = 160
)

// ANSI styling. Two flavors per severity: an "accent" (bold foreground, used
// for section banners and borders) and a "badge" (bold text on a solid
// background, used to highlight the severity tag on each finding line — this
// is the detail that makes one tag pop instead of the whole report looking
// like uniformly-tinted text).
const (
	reset = "\033[0m"
	bold  = "\033[1m"
	dim   = "\033[2m"

	fgRed    = "\033[31m"
	fgYellow = "\033[33m"
	fgBlue   = "\033[34m"
	fgCyan   = "\033[36m"
	fgGreen  = "\033[32m"
	fgGray   = "\033[90m"

	badgeHigh = "\033[1;97;41m" // bold bright-white on red
	badgeMed  = "\033[1;30;43m" // bold black on yellow
	badgeLow  = "\033[1;97;44m" // bold bright-white on blue
	badgeInfo = "\033[1;30;47m" // bold black on light-gray
)

func accent(s model.Severity) string {
	switch s {
	case model.SevHigh:
		return bold + fgRed
	case model.SevMedium:
		return bold + fgYellow
	case model.SevLow:
		return bold + fgBlue
	default:
		return bold + fgGray
	}
}

func badgeColor(s model.Severity) string {
	switch s {
	case model.SevHigh:
		return badgeHigh
	case model.SevMedium:
		return badgeMed
	case model.SevLow:
		return badgeLow
	default:
		return badgeInfo
	}
}

func kindLabel(k model.Kind) string {
	switch k {
	case model.KindHost:
		return "hosts"
	case model.KindPath:
		return "paths"
	case model.KindSub:
		return "subdomains"
	default:
		return string(k)
	}
}

// jsonReport is the top-level JSON envelope. Unaffected by the terminal
// redesign below — this is the stable, machine-readable contract for piping
// into other tools, so its shape never changes with the text renderer.
type jsonReport struct {
	Summary  map[string]int  `json:"summary"`
	Findings []model.Finding `json:"findings"`
	Warnings []string        `json:"warnings,omitempty"`
	Full     []model.Item    `json:"full,omitempty"`
	Sources  []string        `json:"sources,omitempty"`
}

// Render writes a report for the given findings to w.
func Render(w io.Writer, findings []model.Finding, items []model.Item, warnings, sources []string, opt Options) error {
	if opt.JSON {
		return renderJSON(w, findings, items, warnings, sources, opt)
	}
	return renderText(w, findings, items, warnings, sources, opt)
}

func renderJSON(w io.Writer, findings []model.Finding, items []model.Item, warnings, sources []string, opt Options) error {
	rep := jsonReport{
		Summary:  summary(findings),
		Findings: findings,
		Warnings: warnings,
		Sources:  sources,
	}
	if opt.Full {
		rep.Full = items
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func renderText(w io.Writer, findings []model.Finding, items []model.Item, warnings, sources []string, opt Options) error {
	width := opt.Width
	if width < minWidth {
		width = DefaultWidth
	}
	if width > maxWidth {
		width = maxWidth
	}
	col := func(code, s string) string {
		if opt.NoColor {
			return s
		}
		return code + s + reset
	}

	renderBrand(w, sources, col)
	sum := summary(findings)
	renderSummaryBadges(w, sum, col)
	renderLegend(w, col)

	if len(findings) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, col(bold+fgGreen, "  ✓ No findings matched the current filters/ruleset."))
	}

	// Tool-wise layout: one section per source tool, each presented in that
	// tool's own idiom — nmap's service table, ffuf's status/size columns, a
	// resolver-style subdomain list — but enhanced: every row carries a
	// severity badge and an inline "why this matters / what to check" note,
	// and rows are ordered HIGH-first so the must-check items sit at the top
	// of each tool's section. A section is printed only when that tool
	// produced findings, so an nmap-only run shows a single nmap section.
	for _, sec := range []struct {
		kind   model.Kind
		title  string
		render func(io.Writer, []model.Finding, int, func(string, string) string)
	}{
		{model.KindHost, "nmap · hosts & services", renderNmapSection},
		{model.KindPath, "ffuf · discovered content", renderFfufSection},
		{model.KindSub, "subdomains · enumerated names", renderSubsSection},
	} {
		group := filterKind(findings, sec.kind)
		if len(group) == 0 {
			continue
		}
		title := fmt.Sprintf("%s — %d finding%s", sec.title, len(group), plural(len(group)))
		fmt.Fprintln(w)
		// The banner is tinted by the worst finding in the section (findings
		// arrive pre-sorted HIGH-first) so a section containing a HIGH glows
		// red even before you read a row.
		fmt.Fprintln(w, col(accent(group[0].Severity), sectionBanner(title, width)))
		fmt.Fprintln(w)
		sec.render(w, group, width, col)
	}

	if len(warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, col(bold+fgYellow, sectionBanner(fmt.Sprintf("WARNINGS — possible coverage gaps (%d)", len(warnings)), width)))
		fmt.Fprintln(w)
		for _, wn := range warnings {
			fmt.Fprintf(w, "  %s %s\n", col(bold+fgYellow, "⚠"), wn)
		}
	}

	if opt.Full {
		renderFull(w, items, width, col)
	}
	return nil
}

func renderBrand(w io.Writer, sources []string, col func(string, string) string) {
	fmt.Fprintln(w, col(bold+fgCyan, "ptk triage")+col(dim, "  ·  recon findings, ranked"))
	if len(sources) > 0 {
		fmt.Fprintf(w, "%s %s\n", col(dim, "sources:"), strings.Join(sources, ", "))
	}
}

func renderSummaryBadges(w io.Writer, sum map[string]int, col func(string, string) string) {
	fmt.Fprintln(w)
	order := []model.Severity{model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo}
	var parts []string
	for _, sev := range order {
		label := sev.String()
		text := fmt.Sprintf("[ %s %d ]", label, sum[label])
		parts = append(parts, col(badgeColor(sev), text))
	}
	fmt.Fprintln(w, "  "+strings.Join(parts, "  "))
}

func renderLegend(w io.Writer, col func(string, string) string) {
	fmt.Fprintln(w, col(dim, "  HIGH act now  ·  MED worth a look this scan  ·  LOW note for later  ·  INFO context only"))
}

// rowIndent is the visible width consumed by a finding row's leading severity
// badge (" [ HIGH ]  "), so column headers and the "why it matters" reason
// lines can be indented to line up underneath the content, not the badge.
const rowIndent = 11

// badgeRow prints one finding's leading severity badge followed by the
// tool-specific, pre-aligned content columns.
func badgeRow(w io.Writer, col func(string, string) string, sev model.Severity, content string) {
	b := col(badgeColor(sev), fmt.Sprintf("[ %-4s ]", sev.String()))
	fmt.Fprintf(w, " %s  %s\n", b, content)
}

// reasonRow prints the one-line "why this matters / what to check" note beneath
// a finding, tucked under the content with a tree connector so a scan reads as
// "here's the thing → here's what to do about it".
func reasonRow(w io.Writer, col func(string, string) string, reason string) {
	fmt.Fprintf(w, "%s%s %s\n", strings.Repeat(" ", rowIndent), col(fgGray, "└─"), reason)
}

// columnHeader prints a dim, tool-native column header indented to sit above
// the content columns (past the badge).
func columnHeader(w io.Writer, col func(string, string) string, cols string) {
	fmt.Fprintln(w, col(dim, strings.Repeat(" ", rowIndent)+cols))
}

// renderNmapSection presents host findings like nmap's own service table —
// HOST:PORT, SERVICE, VERSION/BANNER — with the worth-checking ports badged
// and annotated.
func renderNmapSection(w io.Writer, fs []model.Finding, width int, col func(string, string) string) {
	targets := make([]string, len(fs))
	svcs := make([]string, len(fs))
	for i, f := range fs {
		targets[i] = f.Target
		svcs[i] = nmapService(f.Item)
	}
	tw := columnWidth(targets, 16, 28)
	sw := columnWidth(svcs, 7, 16)
	verCap := width - rowIndent - tw - sw - 2
	if verCap < 10 {
		verCap = 10
	}

	columnHeader(w, col, fmt.Sprintf("%-*s %-*s %s", tw, "HOST:PORT", sw, "SERVICE", "VERSION / BANNER"))
	for _, f := range fs {
		content := fmt.Sprintf("%s %s %s",
			col(bold+fgCyan, pad(truncate(f.Target, tw), tw)),
			col(fgGreen, pad(truncate(nmapService(f.Item), sw), sw)),
			col(dim, truncate(nmapVersion(f.Item), verCap)))
		badgeRow(w, col, f.Severity, content)
		reasonRow(w, col, f.Reason)
	}
}

// renderFfufSection presents path findings like ffuf's result columns —
// STATUS, SIZE, WORDS, URL — with status codes colored by class so 403s/5xx
// jump out.
func renderFfufSection(w io.Writer, fs []model.Finding, width int, col func(string, string) string) {
	urlCap := width - rowIndent - 26
	if urlCap < 24 {
		urlCap = 24
	}
	columnHeader(w, col, fmt.Sprintf("%-6s %9s %7s  %s", "STATUS", "SIZE", "WORDS", "URL / PATH"))
	for _, f := range fs {
		it := f.Item
		status := "—"
		if it.Status != 0 {
			status = strconv.Itoa(it.Status)
		}
		content := fmt.Sprintf("%s %9s %7s  %s",
			col(statusColor(it.Status), fmt.Sprintf("%-6s", status)),
			commafy(it.Length)+"B",
			commafy(it.Words),
			col(bold+fgCyan, truncate(f.Target, urlCap)))
		badgeRow(w, col, f.Severity, content)
		reasonRow(w, col, f.Reason)
	}
}

// renderSubsSection presents subdomain findings like a resolver dump —
// SUBDOMAIN, RESOLVES TO (A record or "-> cname"), STATE (dangling/http/…) —
// with dangling CNAMEs flagged in red since those are the takeover candidates.
func renderSubsSection(w io.Writer, fs []model.Finding, width int, col func(string, string) string) {
	names := make([]string, len(fs))
	resolves := make([]string, len(fs))
	for i, f := range fs {
		names[i] = f.Target
		resolves[i] = subResolution(f.Item)
	}
	nw := columnWidth(names, 18, 32)
	rw := columnWidth(resolves, 11, 34)

	columnHeader(w, col, fmt.Sprintf("%-*s %-*s %s", nw, "SUBDOMAIN", rw, "RESOLVES TO", "STATE"))
	for _, f := range fs {
		content := fmt.Sprintf("%s %s %s",
			col(bold+fgCyan, pad(truncate(f.Target, nw), nw)),
			pad(truncate(subResolution(f.Item), rw), rw),
			col(subStateColor(f.Item), subState(f.Item)))
		badgeRow(w, col, f.Severity, strings.TrimRight(content, " "))
		reasonRow(w, col, f.Reason)
	}
}

// --- per-tool field formatting --------------------------------------------

func nmapService(it model.Item) string {
	if it.Service != "" {
		return it.Service
	}
	return "—"
}

func nmapVersion(it model.Item) string {
	if v := strings.TrimSpace(it.Banner); v != "" {
		return v
	}
	return strings.TrimSpace(it.Product + " " + it.Version)
}

func subResolution(it model.Item) string {
	switch {
	case it.Address != "":
		return it.Address
	case it.CNAME != "":
		return "-> " + it.CNAME
	default:
		return "-"
	}
}

func subState(it model.Item) string {
	switch {
	case it.Dangling || (it.CNAME != "" && !it.Resolved):
		return "dangling"
	case it.Status != 0:
		return fmt.Sprintf("http %d", it.Status)
	case it.HTTPUp:
		return "http up"
	case it.Resolved:
		return "resolved"
	default:
		return ""
	}
}

func subStateColor(it model.Item) string {
	if it.Dangling || (it.CNAME != "" && !it.Resolved) {
		return bold + fgRed
	}
	return dim
}

// statusColor tints an HTTP status by class: 2xx green, 3xx cyan, 4xx yellow,
// 5xx red — the same at-a-glance coloring ffuf/httpx users expect.
func statusColor(code int) string {
	switch {
	case code >= 500:
		return bold + fgRed
	case code >= 400:
		return bold + fgYellow
	case code >= 300:
		return fgCyan
	case code >= 200:
		return fgGreen
	default:
		return dim
	}
}

// --- small formatting helpers ----------------------------------------------

func filterKind(fs []model.Finding, k model.Kind) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Kind == k {
			out = append(out, f)
		}
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// columnWidth sizes a column to the widest value, floored at min and capped at
// cap so one outlier can't blow out alignment for the whole section.
func columnWidth(vals []string, min, cap int) int {
	w := min
	for _, v := range vals {
		if l := len(v); l > w {
			w = l
		}
	}
	if w > cap {
		w = cap
	}
	return w
}

// commafy renders a non-negative int with thousands separators (1543 ->
// "1,543") so byte sizes and word counts are readable at a glance.
func commafy(n int) string {
	s := strconv.Itoa(n)
	if n < 0 || len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
		b.WriteByte(',')
	}
	for i := pre; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// sectionBanner builds a full-width linPEAS-style header:
// ╔══╣ TITLE ╠══════════════════════════════════...═══╗
func sectionBanner(title string, width int) string {
	left := "╔══╣ " + title + " ╠"
	leftLen := len([]rune(left))
	fillLen := width - leftLen - 1 // reserve 1 for the trailing ╗
	if fillLen < 1 {
		fillLen = 1
	}
	return left + strings.Repeat("═", fillLen) + "╗"
}

// subHeader builds a lighter separator used to introduce a kind-group within
// a severity tier: ── hosts ──────────────────────────────...
func subHeader(title string, width int) string {
	left := "  ── " + title + " "
	leftLen := len([]rune(left))
	fillLen := width - leftLen
	if fillLen < 1 {
		fillLen = 1
	}
	return left + strings.Repeat("─", fillLen)
}

func renderFull(w io.Writer, items []model.Item, width int, col func(string, string) string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, col(bold+fgGray, sectionBanner(fmt.Sprintf("FULL PARSED DATA (%d)", len(items)), width)))

	lastKind := model.Kind("")
	for _, it := range items {
		if it.Kind != lastKind {
			fmt.Fprintln(w)
			fmt.Fprintln(w, col(dim, subHeader(kindLabel(it.Kind), width)))
			lastKind = it.Kind
		}
		switch it.Kind {
		case model.KindHost:
			fmt.Fprintf(w, "  %-22s %-14s %s\n", it.Target(), it.Service, it.Banner)
		case model.KindPath:
			fmt.Fprintf(w, "  %-4d %8dB  %s\n", it.Status, it.Length, it.Target())
		case model.KindSub:
			extra := it.Address
			if it.CNAME != "" {
				extra += " CNAME->" + it.CNAME
			}
			if it.Status != 0 {
				extra += fmt.Sprintf(" http=%d", it.Status)
			}
			fmt.Fprintf(w, "  %-30s %s\n", it.Name, strings.TrimSpace(extra))
		}
	}
}

func summary(fs []model.Finding) map[string]int {
	m := map[string]int{"HIGH": 0, "MED": 0, "LOW": 0, "INFO": 0}
	for _, f := range fs {
		m[f.Severity.String()]++
	}
	return m
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ColorEnabled returns whether the given file is an interactive terminal, used
// to auto-disable color when piping/redirecting.
func ColorEnabled(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// TerminalWidth returns the real width of the given file if it's an
// interactive terminal, or DefaultWidth if it can't be determined (piped,
// redirected, or the query fails) — e.g. when output is captured rather than
// shown live.
func TerminalWidth(f *os.File) int {
	if f == nil {
		return DefaultWidth
	}
	w, _, err := term.GetSize(int(f.Fd()))
	if err != nil || w <= 0 {
		return DefaultWidth
	}
	return w
}

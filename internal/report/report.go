// Package report renders Findings (and optionally the full parsed data) to the
// terminal, or to JSON for piping into other tools.
//
// The terminal format is modeled on the enumeration-script aesthetic (linPEAS/
// winPEAS-style): full-width box-drawn section banners separate severity
// tiers, and each finding's severity tag is rendered as a solid background-
// color "badge" — the same trick those scripts use to make the one piece of
// text that actually matters jump out of a wall of output, instead of relying
// on foreground color alone. Findings arrive pre-sorted (severity, then kind,
// then target), so the HIGH section is always first and is the only thing you
// have to read in a hurry.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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

// tierTitle is the human label used in section banners and the legend.
func tierTitle(s model.Severity) string {
	switch s {
	case model.SevHigh:
		return "HIGH — act now"
	case model.SevMedium:
		return "MEDIUM — worth a look this scan"
	case model.SevLow:
		return "LOW — note for later"
	default:
		return "INFO — context only"
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

	for _, sev := range []model.Severity{model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo} {
		tier := filterSeverity(findings, sev)
		if len(tier) == 0 {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, col(accent(sev), sectionBanner(fmt.Sprintf("%s (%d)", tierTitle(sev), len(tier)), width)))
		fmt.Fprintln(w)
		renderTier(w, tier, width, col)
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

// renderTier prints one severity tier's findings, inserting a dim sub-header
// whenever the item Kind changes — but only when the tier actually mixes
// kinds, so a single-kind tier (the common case for an ffuf-only or nmap-only
// run) stays a clean flat list with no redundant header.
func renderTier(w io.Writer, tier []model.Finding, width int, col func(string, string) string) {
	mixed := false
	for i := 1; i < len(tier); i++ {
		if tier[i].Kind != tier[0].Kind {
			mixed = true
			break
		}
	}

	targetWidth := targetColumnWidth(tier)
	lastKind := model.Kind("")
	for _, f := range tier {
		if mixed && f.Kind != lastKind {
			fmt.Fprintln(w, col(dim, subHeader(kindLabel(f.Kind), width)))
			lastKind = f.Kind
		}
		badge := col(badgeColor(f.Severity), fmt.Sprintf("[ %-4s ]", f.Severity.String()))
		target := col(bold+fgCyan, pad(truncate(f.Target, targetWidth), targetWidth))
		fmt.Fprintf(w, " %s  %s  %s\n", badge, target, f.Reason)
	}
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

func filterSeverity(fs []model.Finding, sev model.Severity) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

func summary(fs []model.Finding) map[string]int {
	m := map[string]int{"HIGH": 0, "MED": 0, "LOW": 0, "INFO": 0}
	for _, f := range fs {
		m[f.Severity.String()]++
	}
	return m
}

// targetColumnWidth sizes the target column to the data, capped so one very
// long path/URL doesn't blow out alignment for the whole tier.
func targetColumnWidth(fs []model.Finding) int {
	width := 0
	for _, f := range fs {
		if l := len(f.Target); l > width && l <= 44 {
			width = l
		}
	}
	if width < 16 {
		width = 16
	}
	return width
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

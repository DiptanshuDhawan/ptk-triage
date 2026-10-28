// Package report renders Findings (and optionally the full parsed data) to the
// terminal with color, or to JSON for piping into other tools.
//
// The terminal format is deliberately dense and scannable: one finding per
// line, severity tag left-aligned, fixed-width target column, reason last. The
// most important lines are at the top because findings arrive pre-sorted.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"ptk/internal/model"
)

// Options controls rendering.
type Options struct {
	JSON    bool // emit machine-readable JSON instead of terminal text
	Full    bool // also print the complete parsed dataset, not just findings
	NoColor bool // disable ANSI color (auto-set when stdout is not a TTY)
}

// ANSI colors. Kept minimal and standard so they render in any terminal.
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cGray   = "\033[90m"
	cGreen  = "\033[32m"
	cCyan   = "\033[36m"
)

func sevColor(s model.Severity) string {
	switch s {
	case model.SevHigh:
		return cRed
	case model.SevMedium:
		return cYellow
	case model.SevLow:
		return cBlue
	default:
		return cGray
	}
}

// jsonReport is the top-level JSON envelope.
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
	col := func(code, s string) string {
		if opt.NoColor {
			return s
		}
		return code + s + cReset
	}

	// Header with severity counts.
	sum := summary(findings)
	fmt.Fprintln(w, col(cBold, "ptk triage report"))
	if len(sources) > 0 {
		fmt.Fprintf(w, "%s %s\n", col(cGray, "sources:"), strings.Join(sources, ", "))
	}
	fmt.Fprintf(w, "%s %s%d  %s%d  %s%d  %s%d%s\n\n",
		col(cGray, "findings:"),
		col(cRed, "HIGH "), sum["HIGH"],
		col(cYellow, "MED "), sum["MED"],
		col(cBlue, "LOW "), sum["LOW"],
		col(cGray, "INFO "), sum["INFO"],
		"")

	if len(findings) == 0 {
		fmt.Fprintln(w, col(cGreen, "No findings matched the current filters/ruleset."))
	}

	// Compute target column width for alignment (capped).
	width := 0
	for _, f := range findings {
		if l := len(f.Target); l > width && l <= 40 {
			width = l
		}
	}
	if width < 16 {
		width = 16
	}

	for _, f := range findings {
		tag := fmt.Sprintf("[%s]", f.Severity.String())
		tag = pad(tag, 7)
		target := pad(f.Target, width)
		line := fmt.Sprintf("%s  %s  %s",
			col(sevColor(f.Severity)+cBold, tag),
			col(cCyan, target),
			f.Reason)
		fmt.Fprintln(w, line)
	}

	// Warnings (coverage gaps) are always shown — they tell the operator what
	// might have been missed.
	if len(warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, col(cYellow+cBold, "warnings (possible coverage gaps):"))
		for _, wn := range warnings {
			fmt.Fprintf(w, "  %s %s\n", col(cYellow, "!"), wn)
		}
	}

	if opt.Full {
		renderFull(w, items, col)
	}
	return nil
}

func renderFull(w io.Writer, items []model.Item, col func(string, string) string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, col(cBold, "full parsed data:"))
	for _, it := range items {
		switch it.Kind {
		case model.KindHost:
			fmt.Fprintf(w, "  %s  %-14s %s %s\n",
				col(cGray, "host"), it.Target(), it.Service, it.Banner)
		case model.KindPath:
			fmt.Fprintf(w, "  %s  %d %7dB  %s\n",
				col(cGray, "path"), it.Status, it.Length, it.Target())
		case model.KindSub:
			extra := it.Address
			if it.CNAME != "" {
				extra += " CNAME->" + it.CNAME
			}
			if it.Status != 0 {
				extra += fmt.Sprintf(" http=%d", it.Status)
			}
			fmt.Fprintf(w, "  %s   %-30s %s\n", col(cGray, "sub"), it.Name, strings.TrimSpace(extra))
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

// ColorEnabled returns whether the given file is an interactive terminal, used
// to auto-disable color when piping/redirecting.
func ColorEnabled(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

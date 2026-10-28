package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ptk/internal/model"
	"ptk/internal/parser/ffuf"
	"ptk/internal/parser/nmap"
	"ptk/internal/parser/subs"
	"ptk/internal/report"
	"ptk/internal/rules"
)

// shared flags, bound once in root and reused across subcommands.
var (
	flagRules       string
	flagJSON        bool
	flagFull        bool
	flagNoColor     bool
	flagOnlyHigh    bool
	flagOnlyHighMed bool
	flagNotes       string
)

// minSeverity derives the severity filter from the --only-* flags.
func minSeverity() model.Severity {
	switch {
	case flagOnlyHigh:
		return model.SevHigh
	case flagOnlyHighMed:
		return model.SevMedium
	default:
		return model.SevInfo
	}
}

// reportOptions builds reporter options, auto-disabling color when stdout is
// not a TTY (so piped/redirected output stays clean) unless JSON is requested.
func reportOptions() report.Options {
	noColor := flagNoColor
	if !report.ColorEnabled(os.Stdout) {
		noColor = true
	}
	return report.Options{JSON: flagJSON, Full: flagFull, NoColor: noColor}
}

// loadRules loads the ruleset and prints any compile warnings to stderr.
func loadRules() (*rules.RuleSet, error) {
	rs, warns, err := rules.Load(flagRules)
	if err != nil {
		return nil, err
	}
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "rules warning: %s\n", w)
	}
	return rs, nil
}

// emit evaluates, filters, renders, and optionally appends to a notes file.
func emit(items []model.Item, warnings, sources []string) error {
	rs, err := loadRules()
	if err != nil {
		return err
	}
	findings := rs.Evaluate(items)
	findings = rules.Filter(findings, minSeverity())

	if err := report.Render(os.Stdout, findings, items, warnings, sources, reportOptions()); err != nil {
		return err
	}
	if flagNotes != "" {
		if err := appendNotes(flagNotes, findings, sources); err != nil {
			fmt.Fprintf(os.Stderr, "notes: %v\n", err)
		}
	}
	return nil
}

// parseByKind dispatches a single file to the right parser. Used by `all`.
func parseByKind(path string) (model.ParseResult, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	switch {
	case ext == ".xml" || strings.Contains(base, "nmap"):
		res, err := nmap.ParseFile(path)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		}
		// Only accept if it actually looked like nmap.
		if len(res.Items) > 0 || containsNmapSignal(path) {
			return res, true
		}
		return model.ParseResult{}, false
	case ext == ".json" || strings.Contains(base, "ffuf"):
		res, err := ffuf.ParseFile(path)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		}
		return res, true
	case ext == ".txt" || ext == ".csv" || ext == ".list" ||
		strings.Contains(base, "sub") || strings.Contains(base, "domain") ||
		strings.Contains(base, "amass") || strings.Contains(base, "subfinder"):
		res, err := subs.ParseFile(path)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		}
		return res, true
	}
	return model.ParseResult{}, false
}

// containsNmapSignal peeks at a file to confirm it is nmap XML before trusting
// the .xml extension.
func containsNmapSignal(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return strings.Contains(string(buf[:n]), "nmaprun")
}

// appendNotes writes flagged findings to a running engagement notes file in a
// readable markdown-ish block (stretch goal).
func appendNotes(path string, findings []model.Finding, sources []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "\n## ptk triage — %s\n", strings.Join(sources, ", "))
	for _, fd := range findings {
		fmt.Fprintf(f, "- [%s] %s — %s\n", fd.Severity.String(), fd.Target, fd.Reason)
	}
	return nil
}

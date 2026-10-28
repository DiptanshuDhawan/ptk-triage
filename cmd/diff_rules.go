package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ptk/internal/diff"
	"ptk/internal/model"
	"ptk/internal/report"

	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff <old> <new>",
	Short: "Show only what changed between two scans (new ports/paths/subs, resolved/dangling CNAMEs, ...)",
	Long: `Compare two recon outputs and report the delta. Old and new may each be a
single file (nmap XML / ffuf JSON / subdomain list) or a folder of outputs —
both sides must be the same shape. Useful between re-scans as an engagement
progresses so you only read what's new.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldItems, oldSrc, err := loadAny(args[0])
		if err != nil {
			return fmt.Errorf("loading old %q: %w", args[0], err)
		}
		newItems, newSrc, err := loadAny(args[1])
		if err != nil {
			return fmt.Errorf("loading new %q: %w", args[1], err)
		}

		d := diff.Compute(oldItems, newItems)
		findings := d.ToFindings()
		findings = filterDiff(findings)

		added, removed, changed := d.Counts()
		sources := []string{fmt.Sprintf("old=%s", oldSrc), fmt.Sprintf("new=%s", newSrc)}

		if !flagJSON {
			fmt.Printf("diff: %d added, %d changed, %d removed\n\n", added, changed, removed)
		}
		// Reuse the reporter; pass both item sets as "full" context only if asked.
		var full []model.Item
		if flagFull {
			full = newItems
		}
		return report.Render(os.Stdout, findings, full, nil, sources, reportOptions())
	},
}

// filterDiff applies the --only-* severity filter to diff findings.
func filterDiff(fs []model.Finding) []model.Finding {
	min := minSeverity()
	var out []model.Finding
	for _, f := range fs {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	return out
}

// loadAny loads items from either a single file or a folder, auto-detecting
// parser by type. Returns the items and a short source label.
func loadAny(path string) ([]model.Item, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, "", err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		var items []model.Item
		for _, name := range names {
			if res, ok := parseByKind(filepath.Join(path, name)); ok {
				items = append(items, res.Items...)
			}
		}
		return items, filepath.Base(path) + "/", nil
	}
	res, ok := parseByKind(path)
	if !ok {
		return nil, "", fmt.Errorf("unrecognized file type (expected nmap .xml, ffuf .json, or subdomain list)")
	}
	return res.Items, filepath.Base(path), nil
}

var dumpRules bool

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Inspect the ruleset: --dump prints the current/default rules YAML",
	RunE: func(cmd *cobra.Command, args []string) error {
		rs, err := loadRules()
		if err != nil {
			return err
		}
		if dumpRules {
			// Print the raw embedded default (with comments) when no custom file
			// is set; otherwise re-read the user's file verbatim.
			if flagRules == "" {
				_, err := os.Stdout.Write(defaultRulesBytes())
				return err
			}
			b, err := os.ReadFile(flagRules)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(b)
			return err
		}
		// Default: summarize loaded rules.
		fmt.Printf("loaded %d pattern rule(s)\n", len(rs.Patterns))
		var ids []string
		for _, p := range rs.Patterns {
			ids = append(ids, fmt.Sprintf("  %-20s %-5s %s", p.ID, p.Severity, p.Field))
		}
		sort.Strings(ids)
		fmt.Println(strings.Join(ids, "\n"))
		fmt.Println("\nbuilt-in computed rules:")
		fmt.Printf("  ffuf: size_outlier=%v (>=%.0f%%, min set %d), interesting_status=%v\n",
			rs.Builtins.SizeOutlier, rs.Builtins.SizeOutlierPct*100, rs.Builtins.SizeOutlierMinSet, rs.Builtins.InterestingStatus)
		fmt.Printf("  nmap: nonstandard_http=%v, nonstandard_ssh=%v, guessed_service=%v, unknown_service=%v\n",
			rs.Builtins.NonStandardHTTP, rs.Builtins.NonStandardSSH, rs.Builtins.GuessedService, rs.Builtins.UnknownService)
		fmt.Printf("  subs: dangling_cname=%v, resolved_no_web=%v, offrange_ip=%v (primary_cidrs=%d), combos=%v\n",
			rs.Builtins.DanglingCNAME, rs.Builtins.ResolvedNoWeb, rs.Builtins.OffRangeIP, len(rs.Builtins.PrimaryCIDRs), rs.Builtins.Combos)
		return nil
	},
}

func init() {
	rulesCmd.Flags().BoolVar(&dumpRules, "dump", false, "print the full rules YAML (with comments) to stdout")
}

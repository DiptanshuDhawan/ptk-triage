// Package cmd wires the ptk triage CLI. Structure mirrors git/docker:
// a root command with subcommands, each parser as its own verb, plus `all`,
// `diff` and `rules`.
package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ptk",
	Short: "ptk — recon triage: signal over noise from nmap/ffuf/subdomain output",
	Long: `ptk triage parses raw recon tool output and surfaces only the findings
worth a human's attention, ranked by severity with a one-line reason for each.

  ptk triage nmap scan.xml
  ptk triage ffuf results.json
  ptk triage subs subs.csv
  ptk triage all ./engagement-outputs
  ptk triage diff old.xml new.xml`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// triageCmd groups the real work under `ptk triage ...`.
var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Triage recon output into a prioritized findings report",
}

// Execute runs the CLI.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(triageCmd)

	// Persistent flags shared by all triage subcommands.
	pf := triageCmd.PersistentFlags()
	pf.StringVar(&flagRules, "rules", "", "path to a custom rules YAML (default: built-in ruleset)")
	pf.BoolVar(&flagJSON, "json", false, "emit JSON instead of a terminal report")
	pf.BoolVar(&flagFull, "full", false, "also show the complete parsed data, not just findings")
	pf.BoolVar(&flagNoColor, "no-color", false, "disable colored output")
	pf.BoolVar(&flagOnlyHigh, "only-high", false, "show only HIGH severity findings")
	pf.BoolVar(&flagOnlyHighMed, "only-high-medium", false, "show only HIGH and MEDIUM findings")
	pf.StringVar(&flagNotes, "notes", "", "append flagged findings to this engagement notes file")

	triageCmd.AddCommand(nmapCmd, ffufCmd, subsCmd, allCmd, diffCmd, rulesCmd)
}

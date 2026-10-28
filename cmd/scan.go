package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"

	"ptk/internal/orchestrator"

	"github.com/spf13/cobra"
)

// scan/doctor flags.
var (
	flagScanOut      string
	flagScanWordlist string
	flagScanNmapArgs string
	flagScanFfufArgs string
	flagScanSkipSubs bool
	flagScanSkipNmap bool
	flagScanSkipFfuf bool
	flagScanProbe    bool
	flagScanMaxFfuf  int
	flagScanDryRun   bool
	flagScanYes      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Orchestrate subfinder/nmap/ffuf against a target, then triage the results",
	Long: `scan drives the real recon tools for you and triages what they produce.

Target may be a domain (subdomain enum + resolve + scan + fuzz), a single IP,
or a CIDR range (scan + fuzz; subdomain enum is skipped). Every tool's native
output is written to an engagement folder, which is then run through the same
pipeline as 'ptk triage all' — so the output, and 'ptk triage diff' between two
runs, work exactly as they do for hand-collected files.

This performs ACTIVE scanning and fuzzing of the target. Only run it against
systems you are authorized to test. Missing tools are skipped with a warning
rather than failing the run; use 'ptk triage doctor' to see what's installed.

  ptk triage scan target.com
  ptk triage scan 10.10.10.5 --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
  ptk triage scan 10.10.10.0/24 --skip-ffuf
  ptk triage scan target.com --dry-run        # print the plan, run nothing`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := orchestrator.ClassifyTarget(args[0])
		if target.Kind == orchestrator.KindUnknown {
			return fmt.Errorf("could not classify target %q as a domain, IP, or CIDR", args[0])
		}

		outDir := flagScanOut
		if outDir == "" {
			outDir = orchestrator.DefaultOutDir(target)
		}

		opts := orchestrator.Options{
			OutDir:   outDir,
			Wordlist: flagScanWordlist,
			NmapArgs: splitArgs(flagScanNmapArgs),
			FfufArgs: splitArgs(flagScanFfufArgs),
			SkipSubs: flagScanSkipSubs,
			SkipNmap: flagScanSkipNmap,
			SkipFfuf: flagScanSkipFfuf,
			Probe:    flagScanProbe,
			MaxFfuf:  flagScanMaxFfuf,
			DryRun:   flagScanDryRun,
		}

		tools := orchestrator.Detect(orchestrator.DefaultTools(), execLookPath)
		flow := orchestrator.NewFlow(indexStatuses(tools), os.Stderr)

		// Dry run: print the plan to stderr and stop, touching nothing.
		if opts.DryRun {
			flow.DryRun(target, opts)
			return nil
		}

		// Active-scan guardrail: a CIDR can mean a very large sweep. Confirm
		// interactively unless --yes was given or stdin isn't a terminal.
		if target.Kind == orchestrator.KindCIDR && !flagScanYes {
			if !confirmCIDR(target.Raw) {
				return fmt.Errorf("aborted; re-run with --yes to scan the whole range %s", target.Raw)
			}
		}

		// Cancel the whole run cleanly on Ctrl+C, then still triage whatever
		// was gathered up to that point.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		fmt.Fprintf(os.Stderr, "ptk triage scan — writing to %s/\n", outDir)
		res, err := flow.Run(ctx, target, opts)
		if err != nil {
			return err
		}

		fmt.Fprintln(os.Stderr)
		if len(res.Ran) > 0 {
			fmt.Fprintf(os.Stderr, "[+] stages run: %s\n", strings.Join(res.Ran, ", "))
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "[!] %s\n", w)
		}
		fmt.Fprintln(os.Stderr)

		// Triage everything the run produced, reusing the exact `all` pipeline.
		items, warnings, sources, matched, err := collectFolder(res.OutDir)
		if err != nil {
			return err
		}
		if matched == 0 {
			fmt.Fprintf(os.Stderr, "no parseable artifacts were produced in %s/ — see the warnings above.\n", res.OutDir)
			return nil
		}
		// Surface run-level warnings alongside parser warnings in the report.
		warnings = append(res.Warnings, warnings...)
		return emit(items, warnings, sources)
	},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Report which external recon tools (subfinder/nmap/ffuf/...) are installed",
	RunE: func(cmd *cobra.Command, args []string) error {
		statuses := orchestrator.Detect(orchestrator.DefaultTools(), execLookPath)
		fmt.Println("ptk triage doctor — external tool availability")
		fmt.Println()
		missing := 0
		for _, s := range statuses {
			if s.Found {
				fmt.Printf("  [ok]   %-12s %s\n", s.Tool.Key, s.Path)
			} else {
				missing++
				fmt.Printf("  [MISS] %-12s %s\n", s.Tool.Key, s.Tool.Purpose)
				fmt.Printf("         install: %s\n", s.Tool.InstallHint())
			}
		}
		fmt.Println()
		if missing == 0 {
			fmt.Println("All tools found — `ptk triage scan` can run every stage.")
		} else {
			fmt.Printf("%d tool(s) missing — scan stages that need them are skipped with a warning.\n", missing)
			fmt.Println("subfinder/nmap/ffuf are the core three; amass/assetfinder are optional enrichment.")
		}
		// Wordlist availability affects the ffuf stage; report it too.
		if wl, ok := orchestrator.FindWordlist("", fileExistsCmd); ok {
			fmt.Printf("\nffuf wordlist: %s\n", wl)
		} else {
			fmt.Println("\nffuf wordlist: none auto-detected — pass --wordlist to `scan` for web fuzzing.")
		}
		return nil
	},
}

// execLookPath is the production PATH lookup, wrapped so orchestrator.Detect
// stays injectable/testable.
func execLookPath(bin string) (string, error) {
	return exec.LookPath(bin)
}

func indexStatuses(statuses []orchestrator.ToolStatus) map[string]orchestrator.ToolStatus {
	m := make(map[string]orchestrator.ToolStatus, len(statuses))
	for _, s := range statuses {
		m[s.Tool.Key] = s
	}
	return m
}

// splitArgs splits a passthrough flag string into argv on whitespace. Complex
// shell quoting is intentionally not supported — document --nmap-args/--ffuf-args
// as space-separated flags.
func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func fileExistsCmd(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// confirmCIDR asks the operator to confirm scanning an entire range.
func confirmCIDR(cidr string) bool {
	fmt.Fprintf(os.Stderr, "About to actively scan the entire range %s. Continue? [y/N] ", cidr)
	var resp string
	fmt.Fscanln(os.Stdin, &resp)
	resp = strings.ToLower(strings.TrimSpace(resp))
	return resp == "y" || resp == "yes"
}

func init() {
	f := scanCmd.Flags()
	f.StringVarP(&flagScanOut, "out", "o", "", "engagement output folder (default: ./ptk-<target>-<timestamp>)")
	f.StringVar(&flagScanWordlist, "wordlist", "", "ffuf wordlist path (default: auto-detect common SecLists/dirb locations)")
	f.StringVar(&flagScanNmapArgs, "nmap-args", "", "override the default nmap scan args entirely (space-separated)")
	f.StringVar(&flagScanFfufArgs, "ffuf-args", "", "extra ffuf flags, e.g. matchers/filters/headers (space-separated)")
	f.BoolVar(&flagScanSkipSubs, "skip-subs", false, "skip subdomain enumeration")
	f.BoolVar(&flagScanSkipNmap, "skip-nmap", false, "skip port/service scanning")
	f.BoolVar(&flagScanSkipFfuf, "skip-ffuf", false, "skip web content fuzzing")
	f.BoolVar(&flagScanProbe, "probe", true, "HTTP-probe resolved subdomains to record live web services")
	f.IntVar(&flagScanMaxFfuf, "max-ffuf", 10, "maximum number of web services to fuzz in one run")
	f.BoolVar(&flagScanDryRun, "dry-run", false, "print the exact plan without running anything or writing files")
	f.BoolVar(&flagScanYes, "yes", false, "skip the confirmation prompt when scanning a CIDR range")

	triageCmd.AddCommand(scanCmd, doctorCmd)
}

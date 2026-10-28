package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"ptk/internal/model"
	"ptk/internal/parser/ffuf"
	"ptk/internal/parser/nmap"
	"ptk/internal/parser/subs"

	"github.com/spf13/cobra"
)

var nmapCmd = &cobra.Command{
	Use:   "nmap <file.xml>",
	Short: "Triage nmap XML (-oX) output",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := nmap.ParseFile(args[0])
		if err != nil {
			return fmt.Errorf("opening nmap file: %w", err)
		}
		return emit(res.Items, res.Warnings, []string{res.Source})
	},
}

var ffufCmd = &cobra.Command{
	Use:   "ffuf <file.json>",
	Short: "Triage ffuf JSON (-of json) output",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := ffuf.ParseFile(args[0])
		if err != nil {
			return fmt.Errorf("opening ffuf file: %w", err)
		}
		return emit(res.Items, res.Warnings, []string{res.Source})
	},
}

var subsCmd = &cobra.Command{
	Use:   "subs <file>",
	Short: "Triage subdomain output (CSV, plain list, amass/subfinder). Reads stdin if file is '-'.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] == "-" {
			res := subs.Parse(os.Stdin)
			res.Source = "stdin"
			return emit(res.Items, res.Warnings, []string{res.Source})
		}
		res, err := subs.ParseFile(args[0])
		if err != nil {
			return fmt.Errorf("opening subs file: %w", err)
		}
		return emit(res.Items, res.Warnings, []string{res.Source})
	},
}

var allCmd = &cobra.Command{
	Use:   "all <folder>",
	Short: "Run all parsers over a folder of outputs and produce one unified report",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := "."
		if len(args) == 1 {
			dir = args[0]
		}
		items, warnings, sources, matched, err := collectFolder(dir)
		if err != nil {
			return err
		}
		if matched == 0 {
			return fmt.Errorf("no recognizable nmap/ffuf/subdomain files found in %q", dir)
		}
		return emit(items, warnings, sources)
	},
}

// collectFolder parses every recognizable file at the top level of dir (it does
// not recurse, so a scan's raw/ provenance subfolder is naturally ignored) and
// returns the merged items, per-file warnings, the matched source names, and
// how many files matched. Parsing runs in parallel — each file is independent
// I/O-plus-CPU work — with results collected index-aligned so the output stays
// deterministic regardless of goroutine scheduling. Shared by `all` and `scan`.
func collectFolder(dir string) (items []model.Item, warnings, sources []string, matched int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("reading folder: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	type outcome struct {
		res model.ParseResult
		ok  bool
	}
	outcomes := make([]outcome, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, path string) {
			defer wg.Done()
			res, ok := parseByKind(path)
			outcomes[i] = outcome{res: res, ok: ok}
		}(i, filepath.Join(dir, name))
	}
	wg.Wait()

	for i, name := range names {
		if !outcomes[i].ok {
			continue
		}
		matched++
		items = append(items, outcomes[i].res.Items...)
		for _, w := range outcomes[i].res.Warnings {
			warnings = append(warnings, fmt.Sprintf("%s: %s", name, w))
		}
		sources = append(sources, name)
	}
	return items, warnings, sources, matched, nil
}

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

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
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("reading folder: %w", err)
		}

		var allItems []model.Item
		var allWarnings, sources []string
		matched := 0

		// Stable order for deterministic reports.
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)

		for _, name := range names {
			path := filepath.Join(dir, name)
			res, ok := parseByKind(path)
			if !ok {
				continue
			}
			matched++
			allItems = append(allItems, res.Items...)
			for _, w := range res.Warnings {
				allWarnings = append(allWarnings, fmt.Sprintf("%s: %s", name, w))
			}
			sources = append(sources, name)
		}

		if matched == 0 {
			return fmt.Errorf("no recognizable nmap/ffuf/subdomain files found in %q", dir)
		}
		return emit(allItems, allWarnings, sources)
	},
}

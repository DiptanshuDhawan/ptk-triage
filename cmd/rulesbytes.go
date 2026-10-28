package cmd

import "ptk/internal/rules"

// defaultRulesBytes exposes the embedded default ruleset (with comments) to the
// `rules --dump` command.
func defaultRulesBytes() []byte { return rules.DefaultYAML() }

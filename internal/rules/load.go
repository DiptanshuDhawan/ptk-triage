package rules

import (
	_ "embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// defaultYAML is the seeded ruleset, compiled into the binary so the tool works
// with zero config. Users can dump it (`ptk triage rules --dump`) and point
// --rules at an edited copy.
//
//go:embed default_rules.yaml
var defaultYAML []byte

// Load reads a ruleset. If path is empty, the embedded default is used.
// It returns the compiled RuleSet plus any non-fatal warnings (bad individual
// rules / CIDRs) so the caller can surface them without failing the whole run.
func Load(path string) (*RuleSet, []string, error) {
	data := defaultYAML
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("reading rules file %q: %w", path, err)
		}
		data = b
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, nil, fmt.Errorf("parsing rules YAML: %w", err)
	}
	warns := rs.compile()
	return &rs, warns, nil
}

// DefaultYAML returns the embedded default ruleset bytes (for `rules --dump`).
func DefaultYAML() []byte { return defaultYAML }

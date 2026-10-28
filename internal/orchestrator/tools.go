package orchestrator

import "runtime"

// Tool describes an external recon binary ptk can drive. Bins lists candidate
// executable names to look up on PATH, in preference order (e.g. a tool might
// be "subfinder" or shipped as "subfinder.exe" — exec.LookPath handles the
// .exe on Windows automatically, so we list the base name only).
type Tool struct {
	Key     string            // stable identifier used in flags/warnings
	Bins    []string          // candidate binary names, preference order
	Purpose string            // one-line description for `doctor`
	Install map[string]string // GOOS -> install hint
}

// DefaultTools is the set ptk knows how to orchestrate. subfinder is the only
// subdomain tool required for the domain flow; amass/assetfinder are optional
// enrichment used when present.
func DefaultTools() []Tool {
	return []Tool{
		{
			Key:     "subfinder",
			Bins:    []string{"subfinder"},
			Purpose: "passive subdomain enumeration (domain targets)",
			Install: map[string]string{
				"linux":   "sudo apt install subfinder   # or: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
				"darwin":  "brew install subfinder",
				"windows": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest   (then add %USERPROFILE%\\go\\bin to PATH)",
			},
		},
		{
			Key:     "amass",
			Bins:    []string{"amass"},
			Purpose: "additional subdomain enumeration (optional, enriches subfinder)",
			Install: map[string]string{
				"linux":   "sudo apt install amass   # or: go install github.com/owasp-amass/amass/v4/...@master",
				"darwin":  "brew install amass",
				"windows": "go install github.com/owasp-amass/amass/v4/...@master",
			},
		},
		{
			Key:     "assetfinder",
			Bins:    []string{"assetfinder"},
			Purpose: "additional subdomain enumeration (optional, enriches subfinder)",
			Install: map[string]string{
				"linux":   "go install github.com/tomnomnom/assetfinder@latest",
				"darwin":  "brew install assetfinder",
				"windows": "go install github.com/tomnomnom/assetfinder@latest",
			},
		},
		{
			Key:     "nmap",
			Bins:    []string{"nmap"},
			Purpose: "port/service scanning (all target kinds)",
			Install: map[string]string{
				"linux":   "sudo apt install nmap",
				"darwin":  "brew install nmap",
				"windows": "winget install Insecure.Nmap   (installs Npcap; SYN scans need Administrator — ptk defaults to a connect scan that does not)",
			},
		},
		{
			Key:     "ffuf",
			Bins:    []string{"ffuf"},
			Purpose: "web content fuzzing (hosts with an open HTTP/S port)",
			Install: map[string]string{
				"linux":   "sudo apt install ffuf   # or: go install github.com/ffuf/ffuf/v2@latest",
				"darwin":  "brew install ffuf",
				"windows": "go install github.com/ffuf/ffuf/v2@latest   (then add %USERPROFILE%\\go\\bin to PATH)",
			},
		},
	}
}

// ToolStatus is the result of looking for one tool on the system.
type ToolStatus struct {
	Tool  Tool
	Path  string // resolved absolute path, or "" if not found
	Found bool
}

// InstallHint returns the OS-appropriate install instruction, falling back to
// the linux hint for unlisted platforms.
func (t Tool) InstallHint() string {
	if h, ok := t.Install[runtime.GOOS]; ok {
		return h
	}
	return t.Install["linux"]
}

// LookPathFunc matches exec.LookPath, injected so detection is testable without
// touching the real PATH.
type LookPathFunc func(string) (string, error)

// Detect resolves each tool against PATH via lookPath.
func Detect(tools []Tool, lookPath LookPathFunc) []ToolStatus {
	out := make([]ToolStatus, 0, len(tools))
	for _, t := range tools {
		st := ToolStatus{Tool: t}
		for _, bin := range t.Bins {
			if p, err := lookPath(bin); err == nil && p != "" {
				st.Path = p
				st.Found = true
				break
			}
		}
		out = append(out, st)
	}
	return out
}

// statusIndex builds a key->status map for quick lookups during planning.
func statusIndex(statuses []ToolStatus) map[string]ToolStatus {
	m := make(map[string]ToolStatus, len(statuses))
	for _, s := range statuses {
		m[s.Tool.Key] = s
	}
	return m
}

// Package model defines the normalized, source-agnostic data structures that
// all parsers emit and that the rule engine and reporters consume.
//
// The central idea: nmap, ffuf and subdomain outputs are wildly different on
// disk, but once parsed they are reduced to a flat list of Items. A rule never
// needs to know which tool produced an Item — it matches against typed fields
// that are present or empty depending on Kind. This keeps the engine stable
// while parsers and rules evolve independently.
package model

import (
	"fmt"
	"sort"
	"strings"
)

// Kind identifies which recon domain an Item came from.
type Kind string

const (
	KindHost Kind = "host" // an nmap host:port/service
	KindPath Kind = "path" // an ffuf discovered path
	KindSub  Kind = "sub"  // an enumerated subdomain
)

// Severity ranks how much attention a finding deserves.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
)

// String renders a severity as the short uppercase token used in reports.
func (s Severity) String() string {
	switch s {
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MED"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// ParseSeverity converts a rules-file token (case-insensitive) into a Severity.
// Unknown values default to INFO so a typo in a rule never silently promotes a
// finding to HIGH.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HIGH":
		return SevHigh
	case "MED", "MEDIUM":
		return SevMedium
	case "LOW":
		return SevLow
	default:
		return SevInfo
	}
}

// Item is the normalized unit of parsed recon data. Not every field is relevant
// for every Kind; irrelevant fields are left zero. The matchable string fields
// (Service, Banner, Path, Name, Scripts) are what rules regex against.
type Item struct {
	Kind Kind `json:"kind"`

	// Host / network identity. Present for host and sub items.
	Address string `json:"address,omitempty"` // IP address
	Host    string `json:"host,omitempty"`    // hostname / FQDN

	// nmap host fields.
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // tcp / udp
	State    string `json:"state,omitempty"`    // open / filtered / ...
	Service  string `json:"service,omitempty"`  // e.g. http, ssh, microsoft-ds
	Product  string `json:"product,omitempty"`  // e.g. OpenSSH, Apache httpd
	Version  string `json:"version,omitempty"`  // e.g. 7.2p2
	Banner   string `json:"banner,omitempty"`   // combined product+version+extrainfo
	Scripts  string `json:"scripts,omitempty"`  // concatenated NSE script output

	// ffuf path fields.
	URL    string `json:"url,omitempty"`
	Path   string `json:"path,omitempty"`   // the FUZZ value / input
	Status int    `json:"status,omitempty"` // HTTP status code
	Length int    `json:"length,omitempty"` // response size in bytes
	Words  int    `json:"words,omitempty"`
	Lines  int    `json:"lines,omitempty"`
	Redir  string `json:"redirect,omitempty"` // Location header target, if any

	// subdomain fields.
	Name     string `json:"name,omitempty"`     // the subdomain FQDN
	Resolved bool   `json:"resolved,omitempty"` // did it resolve to an IP?
	CNAME    string `json:"cname,omitempty"`    // CNAME target if known
	Dangling bool   `json:"dangling,omitempty"` // CNAME points at nothing live
	HTTPUp   bool   `json:"http_up,omitempty"`  // an HTTP(S) service answered

	// Extra carries anything source-specific a reporter may want in --full mode.
	Extra map[string]string `json:"extra,omitempty"`
}

// Key returns a stable identity string for the Item, used by diff mode to tell
// whether two items from different scans represent the same thing.
func (i Item) Key() string {
	switch i.Kind {
	case KindHost:
		return fmt.Sprintf("host|%s|%d/%s", i.Address, i.Port, i.Protocol)
	case KindPath:
		if i.URL != "" {
			return "path|" + i.URL
		}
		return "path|" + i.Path
	case KindSub:
		return "sub|" + strings.ToLower(i.Name)
	}
	return "unknown|" + i.Address
}

// Target is the short, human-facing locator shown in a report line, e.g.
// "10.10.10.5:445" or "dev.target.com".
func (i Item) Target() string {
	switch i.Kind {
	case KindHost:
		return fmt.Sprintf("%s:%d", i.Address, i.Port)
	case KindPath:
		if i.URL != "" {
			return i.URL
		}
		return i.Path
	case KindSub:
		return i.Name
	}
	return i.Address
}

// Finding is the output of the rule engine: an Item plus why it was flagged.
type Finding struct {
	Item     Item     `json:"-"`
	Kind     Kind     `json:"kind"`
	Target   string   `json:"target"`
	Severity Severity `json:"-"`
	SevLabel string   `json:"severity"`
	RuleID   string   `json:"rule"`
	Reason   string   `json:"reason"`
}

// SortFindings orders findings by severity (HIGH first), then kind, then target
// so reports are deterministic and the most important lines appear at the top.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(a, b int) bool {
		if fs[a].Severity != fs[b].Severity {
			return fs[a].Severity > fs[b].Severity
		}
		if fs[a].Kind != fs[b].Kind {
			return fs[a].Kind < fs[b].Kind
		}
		return fs[a].Target < fs[b].Target
	})
}

// ParseResult bundles the normalized items a parser produced with any
// non-fatal problems it hit. The engine never throws away a partial parse:
// Warnings surface what could not be read so the operator knows coverage gaps.
type ParseResult struct {
	Items    []Item
	Warnings []string
	Source   string // file or label the data came from
}

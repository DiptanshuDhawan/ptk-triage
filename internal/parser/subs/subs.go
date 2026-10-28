// Package subs parses subdomain enumeration data into normalized model.Items.
//
// Input is intentionally flexible because subdomain data arrives in many
// shapes. We auto-detect and normalize:
//
//   - CSV / delimited:  "subdomain,ip,status"  (missing trailing fields OK)
//   - plain list:       one FQDN per line
//   - subfinder/assetfinder: plain FQDNs (same as plain list)
//   - amass "normal":   "name <A|CNAME> target" lines, e.g.
//     "dev.target.com (FQDN) --> cname_record --> dev.target.com.s3.amazonaws.com (FQDN)"
//     and the simpler "host.target.com   1.2.3.4" two-column form.
//
// Fields that cannot be determined are left empty; a later resolver step or the
// rule engine decides what that means. We never discard a line we recognize as
// a hostname.
package subs

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"ptk/internal/model"
)

var (
	// A permissive hostname matcher: labels of letters/digits/hyphens joined by
	// dots, with a final alphabetic TLD of 2+ chars. Good enough to tell a
	// hostname apart from noise/log lines.
	reHost = regexp.MustCompile(`^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	// amass arrow form: "<name> (FQDN) --> <relation> --> <target> (TYPE)"
	reAmassArrow = regexp.MustCompile(`^(\S+)\s+\((?:FQDN|[^)]+)\)\s+-->\s+(\S+)\s+-->\s+(\S+)`)
)

// ParseFile reads and parses a subdomain input file.
func ParseFile(path string) (model.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.ParseResult{Source: path}, err
	}
	defer f.Close()
	res := Parse(f)
	res.Source = path
	return res, nil
}

// Parse consumes subdomain data from any supported format.
func Parse(r io.Reader) model.ParseResult {
	var res model.ParseResult
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // allow long lines

	seen := map[string]int{} // name -> index in res.Items, for merge/dedupe
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		it, ok := parseLine(raw)
		if !ok {
			// Only warn on lines that looked like they were trying to be data.
			if looksLikeData(raw) {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("line %d: could not interpret %q", lineNo, truncate(raw, 60)))
			}
			continue
		}
		mergeItem(&res, seen, it)
	}
	if err := sc.Err(); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("read error: %v", err))
	}
	if len(res.Items) == 0 && len(res.Warnings) == 0 {
		res.Warnings = append(res.Warnings, "no subdomains recognized in input")
	}
	return res
}

func parseLine(line string) (model.Item, bool) {
	// amass arrow form first — it is the most structured.
	if m := reAmassArrow.FindStringSubmatch(line); m != nil {
		name := strings.TrimSuffix(m[1], ".")
		rel := strings.ToLower(m[2])
		target := strings.TrimSuffix(m[3], ".")
		it := model.Item{Kind: model.KindSub, Name: name, Extra: map[string]string{}}
		switch {
		case net.ParseIP(target) != nil:
			it.Address = target
			it.Resolved = true
		case strings.Contains(rel, "cname"):
			it.CNAME = target
		case reHost.MatchString(target):
			it.CNAME = target
		}
		if !reHost.MatchString(name) {
			return model.Item{}, false
		}
		return it, true
	}

	// Delimited forms: comma, tab, or run of spaces.
	fields := splitFlexible(line)
	if len(fields) == 0 {
		return model.Item{}, false
	}
	name := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
	if !reHost.MatchString(name) {
		return model.Item{}, false
	}
	it := model.Item{Kind: model.KindSub, Name: name, Extra: map[string]string{}}

	for _, f := range fields[1:] {
		f = strings.TrimSpace(f)
		switch {
		case f == "":
			continue
		case net.ParseIP(strings.Trim(f, "[]")) != nil:
			it.Address = strings.Trim(f, "[]")
			it.Resolved = true
		case isStatus(f):
			code, _ := strconv.Atoi(f)
			it.Status = code
			it.HTTPUp = code > 0
		case reHost.MatchString(f):
			// A second hostname in the row is treated as a CNAME target.
			if it.CNAME == "" {
				it.CNAME = strings.TrimSuffix(strings.ToLower(f), ".")
			}
		}
	}
	return it, true
}

// mergeItem folds a newly parsed item into the result, enriching an existing
// entry for the same name rather than creating a duplicate. This lets a plain
// list and a resolved CSV for the same host combine cleanly.
func mergeItem(res *model.ParseResult, seen map[string]int, it model.Item) {
	if idx, ok := seen[it.Name]; ok {
		cur := &res.Items[idx]
		if cur.Address == "" && it.Address != "" {
			cur.Address = it.Address
			cur.Resolved = true
		}
		if cur.CNAME == "" && it.CNAME != "" {
			cur.CNAME = it.CNAME
		}
		if it.Status != 0 {
			cur.Status = it.Status
			cur.HTTPUp = it.HTTPUp
		}
		return
	}
	seen[it.Name] = len(res.Items)
	res.Items = append(res.Items, it)
}

// splitFlexible splits on comma first (CSV), else on any whitespace run.
func splitFlexible(line string) []string {
	if strings.Contains(line, ",") {
		parts := strings.Split(line, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	return strings.Fields(line)
}

func isStatus(s string) bool {
	if len(s) != 3 {
		return false
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 100 && n < 600
}

func looksLikeData(line string) bool {
	// Contains a dot and no spaces-only content; avoids warning on banners.
	return strings.Contains(line, ".") && len(strings.Fields(line)) <= 6
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

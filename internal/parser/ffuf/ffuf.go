// Package ffuf parses ffuf JSON output (-o results.json -of json) into
// normalized model.Items.
//
// ffuf's JSON shape is: { "results": [ {input, status, length, words, lines,
// url, redirectlocation, ...}, ... ], ... }. The "input" field is itself an
// object keyed by the fuzz keyword (usually FUZZ), so we tolerate either a
// string or an object there.
//
// Robustness: truncated ffuf output (e.g. the process was killed mid-write)
// yields invalid JSON. Rather than return nothing, we fall back to a
// line/record salvage pass that recovers whole result objects that were fully
// written before truncation.
package ffuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"ptk/internal/model"
)

type ffufFile struct {
	Results []result `json:"results"`
}

type result struct {
	Input            inputField `json:"input"`
	URL              string     `json:"url"`
	Status           int        `json:"status"`
	Length           int        `json:"length"`
	Words            int        `json:"words"`
	Lines            int        `json:"lines"`
	RedirectLocation string     `json:"redirectlocation"`
	ContentType      string     `json:"content-type"`
	Host             string     `json:"host"`
}

// inputField decodes ffuf's "input" which is normally an object like
// {"FUZZ":"admin"} but can be a bare string in older/odd outputs.
type inputField struct {
	val string
}

func (f *inputField) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	if b[0] == '"' {
		return json.Unmarshal(b, &f.val)
	}
	if b[0] == '{' {
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		// Prefer the canonical FUZZ keyword; otherwise take any value.
		if v, ok := m["FUZZ"]; ok {
			f.val = v
			return nil
		}
		for _, v := range m {
			f.val = v
			return nil
		}
	}
	return nil
}

// ParseFile reads and parses an ffuf JSON file.
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

// Parse consumes an ffuf JSON stream, degrading gracefully on truncation.
func Parse(r io.Reader) model.ParseResult {
	var res model.ParseResult
	data, err := io.ReadAll(r)
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("read error: %v", err))
		return res
	}

	var ff ffufFile
	if err := json.Unmarshal(data, &ff); err == nil {
		for _, r := range ff.Results {
			res.Items = append(res.Items, resultToItem(r))
		}
		if len(ff.Results) == 0 {
			res.Warnings = append(res.Warnings, "ffuf JSON parsed but contained no results")
		}
		return res
	}

	// Clean parse failed — attempt salvage of whole result objects.
	salvaged, n := salvage(data)
	res.Items = append(res.Items, salvaged...)
	res.Warnings = append(res.Warnings,
		fmt.Sprintf("ffuf JSON was malformed/truncated; salvaged %d complete result record(s)", n))
	return res
}

func resultToItem(r result) model.Item {
	it := model.Item{
		Kind:   model.KindPath,
		URL:    r.URL,
		Path:   r.Input.val,
		Status: r.Status,
		Length: r.Length,
		Words:  r.Words,
		Lines:  r.Lines,
		Redir:  r.RedirectLocation,
		Host:   r.Host,
		Extra:  map[string]string{},
	}
	if r.ContentType != "" {
		it.Extra["content_type"] = r.ContentType
	}
	return it
}

// salvage scans a truncated results array and extracts every balanced {...}
// object inside it, decoding each independently. This recovers all records
// written before the truncation point.
func salvage(data []byte) ([]model.Item, int) {
	idx := bytes.Index(data, []byte(`"results"`))
	if idx < 0 {
		return nil, 0
	}
	// Advance to the opening '[' of the results array.
	start := bytes.IndexByte(data[idx:], '[')
	if start < 0 {
		return nil, 0
	}
	buf := data[idx+start+1:]

	var items []model.Item
	depth := 0
	objStart := -1
	inStr := false
	esc := false
	for i := 0; i < len(buf); i++ {
		c := buf[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				objStart = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 && objStart >= 0 {
				var r result
				if err := json.Unmarshal(buf[objStart:i+1], &r); err == nil {
					items = append(items, resultToItem(r))
				}
				objStart = -1
			}
		case ']':
			if depth == 0 {
				return items, len(items)
			}
		}
	}
	return items, len(items)
}

// Baseline computes the most common response length ("noise floor") across a
// set of path items. Reporters/rules use it to flag size outliers — the entries
// that deviate from the sea of identical 404/200-wildcard responses are the
// ones worth a look. Returns the modal length and how many items shared it.
func Baseline(items []model.Item) (length int, count int) {
	freq := map[int]int{}
	for _, it := range items {
		if it.Kind != model.KindPath {
			continue
		}
		freq[it.Length]++
	}
	for l, c := range freq {
		if c > count || (c == count && l < length) {
			length, count = l, c
		}
	}
	return length, count
}

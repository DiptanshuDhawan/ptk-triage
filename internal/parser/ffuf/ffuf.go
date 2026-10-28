// Package ffuf parses ffuf JSON output (-o results.json -of json) into
// normalized model.Items.
//
// ffuf's JSON shape is: { "results": [ {input, status, length, words, lines,
// url, redirectlocation, ...}, ... ], ... }. The "input" field is itself an
// object keyed by the fuzz keyword (usually FUZZ), so we tolerate either a
// string or an object there.
//
// Parsing is a single streaming pass over the input using encoding/json's
// token-based Decoder, rather than buffering the whole file and attempting a
// one-shot Unmarshal. This matters for two reasons:
//
//  1. Efficiency: a large wordlist run can produce a multi-hundred-MB JSON
//     file. Decoder reads incrementally from the source, so the clean/common
//     case never holds the entire file as one contiguous byte slice in memory
//     alongside the parsed structure — unlike io.ReadAll + json.Unmarshal.
//  2. Robustness: truncated ffuf output (e.g. the process was killed
//     mid-write) yields invalid JSON. Streaming decode naturally recovers
//     every complete result record decoded before the cut, with no separate
//     hand-rolled byte-scanning fallback needed — the same single pass
//     handles both the clean and the truncated case.
package ffuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"ptk/internal/model"
)

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
	items, truncated, foundResults, err := streamDecode(r)
	res.Items = items

	switch {
	case err != nil:
		res.Warnings = append(res.Warnings, fmt.Sprintf("ffuf JSON could not be parsed: %v", err))
	case !foundResults:
		res.Warnings = append(res.Warnings, `no "results" array found — is this ffuf JSON (-of json) output?`)
	case truncated:
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("ffuf JSON was truncated/malformed; recovered %d complete result record(s) before the cut", len(items)))
	case len(items) == 0:
		res.Warnings = append(res.Warnings, "ffuf JSON parsed but contained no results")
	}
	return res
}

// streamDecode walks the top-level JSON object looking for the "results" key,
// decoding each array element individually. Sibling keys (commandline, time,
// config, ...) are skipped generically without being fully typed. Once the
// results array has been consumed (cleanly or not), parsing stops — a
// truncation AFTER a complete results array (e.g. in a trailing "config"
// block) must not be reported as lost findings, since nothing we care about
// was actually dropped.
//
// truncated distinguishes "the results array did not close cleanly" (some
// element failed to decode, or EOF arrived before the closing bracket) from a
// normal, complete parse — including the subtle case where the stream ends
// exactly on a trailing comma with no closing bracket at all: in that case
// json.Decoder.More() itself can't tell, so after an apparently-clean loop
// exit we explicitly try to consume the closing ']' and treat failure to do
// so as truncation too.
func streamDecode(r io.Reader) (items []model.Item, truncated bool, foundResults bool, err error) {
	dec := json.NewDecoder(r)

	tok, e := dec.Token()
	if e != nil {
		return nil, false, false, e
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, false, false, fmt.Errorf("expected a JSON object at the top level")
	}

	for dec.More() {
		keyTok, e := dec.Token()
		if e != nil {
			return items, true, foundResults, nil
		}
		key, _ := keyTok.(string)
		if key != "results" {
			var discard any
			if e := dec.Decode(&discard); e != nil {
				return items, true, foundResults, nil
			}
			continue
		}

		foundResults = true
		arrTok, e := dec.Token()
		if e != nil {
			return items, true, true, nil
		}
		if d, ok := arrTok.(json.Delim); !ok || d != '[' {
			return items, true, true, nil
		}

		for dec.More() {
			var rr result
			if e := dec.Decode(&rr); e != nil {
				return items, true, true, nil
			}
			items = append(items, resultToItem(rr))
		}
		// dec.More() returning false is ambiguous: it also returns false on a
		// read error/EOF while peeking (e.g. the stream ends right after a
		// trailing comma, before any closing bracket was ever written).
		// Confirm the array really closed by consuming the ']' explicitly.
		closeTok, e := dec.Token()
		if e != nil {
			return items, true, true, nil
		}
		if d, ok := closeTok.(json.Delim); !ok || d != ']' {
			return items, true, true, nil
		}
		return items, false, true, nil
	}
	return items, false, foundResults, nil
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

// Baseline computes the most common response length ("noise floor") across a
// set of path items. Reporters/rules use it to flag size outliers — the entries
// that deviate from the sea of identical 404/200-wildcard responses are the
// ones worth a look. Returns the modal length and how many items shared it.
//
// NOTE: this is a global (all-statuses) baseline, kept as a general-purpose
// utility. The rule engine itself computes a more precise PER-STATUS-CODE
// baseline internally (see internal/rules) since mixing statuses into one
// baseline is prone to false positives/negatives.
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

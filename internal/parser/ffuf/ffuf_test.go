package ffuf

import (
	"strings"
	"testing"

	"ptk/internal/model"
)

const sampleJSON = `{
  "results": [
    {"input": {"FUZZ": "admin"}, "status": 403, "length": 289, "words": 20, "lines": 10, "url": "http://t/admin"},
    {"input": {"FUZZ": ".env"}, "status": 200, "length": 431, "words": 30, "lines": 18, "url": "http://t/.env"},
    {"input": {"FUZZ": "home"}, "status": 200, "length": 1256, "words": 120, "lines": 40, "url": "http://t/home"},
    {"input": {"FUZZ": "about"}, "status": 200, "length": 1256, "words": 120, "lines": 40, "url": "http://t/about"},
    {"input": {"FUZZ": "go"}, "status": 302, "length": 0, "redirectlocation": "/login", "url": "http://t/go"}
  ]
}`

func TestParseBasic(t *testing.T) {
	res := Parse(strings.NewReader(sampleJSON))
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", res.Warnings)
	}
	if len(res.Items) != 5 {
		t.Fatalf("expected 5 items, got %d", len(res.Items))
	}

	first := res.Items[0]
	if first.Kind != model.KindPath || first.Status != 403 || first.Length != 289 {
		t.Errorf("first item wrong: %+v", first)
	}
	if first.Path != "admin" {
		t.Errorf("expected input FUZZ value 'admin', got %q", first.Path)
	}
	// redirect carried through.
	last := res.Items[4]
	if last.Redir != "/login" {
		t.Errorf("redirect not captured: %+v", last)
	}
}

func TestInputAsString(t *testing.T) {
	// Older ffuf output where input is a bare string.
	j := `{"results":[{"input":"backup.zip","status":200,"length":99,"url":"http://t/backup.zip"}]}`
	res := Parse(strings.NewReader(j))
	if len(res.Items) != 1 || res.Items[0].Path != "backup.zip" {
		t.Fatalf("string input not handled: %+v", res.Items)
	}
}

func TestBaseline(t *testing.T) {
	res := Parse(strings.NewReader(sampleJSON))
	length, count := Baseline(res.Items)
	if length != 1256 || count != 2 {
		t.Errorf("expected modal length 1256 x2, got %d x%d", length, count)
	}
}

func TestTruncatedSalvage(t *testing.T) {
	// Cut off mid-array after two complete objects.
	idx := strings.Index(sampleJSON, `{"input": {"FUZZ": "home"}`)
	truncated := sampleJSON[:idx]
	res := Parse(strings.NewReader(truncated))
	if len(res.Warnings) == 0 {
		t.Error("expected a salvage warning")
	}
	if len(res.Items) != 2 {
		t.Fatalf("expected 2 salvaged items, got %d: %+v", len(res.Items), res.Items)
	}
	if res.Items[0].Path != "admin" || res.Items[1].Path != ".env" {
		t.Errorf("salvaged wrong items: %+v", res.Items)
	}
}

func TestEmptyResults(t *testing.T) {
	res := Parse(strings.NewReader(`{"results":[]}`))
	if len(res.Items) != 0 {
		t.Error("expected no items")
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning about empty results")
	}
}

func TestGarbageInput(t *testing.T) {
	res := Parse(strings.NewReader(`totally not json`))
	// Should not panic; salvage finds nothing.
	if len(res.Items) != 0 {
		t.Error("garbage should yield no items")
	}
}

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ptk/internal/model"
)

func sampleFindings() []model.Finding {
	return []model.Finding{
		{Kind: model.KindHost, Target: "10.0.0.1:445", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "smb", Reason: "SMB exposed"},
		{Kind: model.KindPath, Target: "http://t/.env", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "path-env", Reason: "env exposed"},
		{Kind: model.KindHost, Target: "10.0.0.1:135", Severity: model.SevMedium, SevLabel: "MED", RuleID: "msrpc", Reason: "MSRPC endpoint mapper"},
		{Kind: model.KindSub, Target: "dev.target.com", Severity: model.SevLow, SevLabel: "LOW", RuleID: "resolved-no-web", Reason: "no web service seen"},
	}
}

func TestNoColorStripsAllEscapeSequences(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, sampleFindings(), nil, nil, []string{"scan.xml"}, Options{NoColor: true, Width: DefaultWidth})
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	out := buf.String()
	if strings.ContainsRune(out, '\x1b') {
		t.Error("NoColor output must not contain any ANSI escape byte")
	}
	// Structural content must still be present in plain mode.
	for _, want := range []string{"HIGH", "MED", "LOW", "10.0.0.1:445", "SMB exposed", "dev.target.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in plain-text output", want)
		}
	}
}

func TestColorOutputHasExpectedBadgeCodes(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, sampleFindings(), nil, nil, nil, Options{NoColor: false, Width: DefaultWidth})
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, badgeHigh) {
		t.Error("expected the HIGH badge color code in colored output")
	}
	if !strings.Contains(out, badgeMed) {
		t.Error("expected the MED badge color code in colored output")
	}
	if !strings.Contains(out, badgeLow) {
		t.Error("expected the LOW badge color code in colored output")
	}
	if !strings.Contains(out, reset) {
		t.Error("expected ANSI reset codes to close colored spans")
	}
}

func TestSeverityTiersAppearInOrder(t *testing.T) {
	var buf bytes.Buffer
	_ = Render(&buf, sampleFindings(), nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()

	highIdx := strings.Index(out, "HIGH — act now")
	medIdx := strings.Index(out, "MEDIUM — worth a look")
	lowIdx := strings.Index(out, "LOW — note for later")
	if highIdx < 0 || medIdx < 0 || lowIdx < 0 {
		t.Fatalf("missing a section banner; output:\n%s", out)
	}
	if !(highIdx < medIdx && medIdx < lowIdx) {
		t.Error("severity section banners must appear HIGH, then MED, then LOW")
	}
	// No findings were INFO-severity, so that banner must not appear at all.
	if strings.Contains(out, "INFO — context only (") {
		// The legend line mentions "INFO context only" without a count — only
		// the section BANNER (with a parenthesized count) should be absent.
		if strings.Contains(out, "╣ INFO") {
			t.Error("INFO section banner should not render when there are no INFO findings")
		}
	}
}

func TestMixedKindTierGetsSubHeaders(t *testing.T) {
	fs := []model.Finding{
		{Kind: model.KindHost, Target: "10.0.0.1:445", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "smb", Reason: "x"},
		{Kind: model.KindPath, Target: "http://t/.env", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "path-env", Reason: "y"},
	}
	var buf bytes.Buffer
	_ = Render(&buf, fs, nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	if !strings.Contains(out, "── hosts") || !strings.Contains(out, "── paths") {
		t.Errorf("expected both kind sub-headers in a mixed-kind tier, got:\n%s", out)
	}
}

func TestSingleKindTierHasNoSubHeader(t *testing.T) {
	fs := []model.Finding{
		{Kind: model.KindHost, Target: "10.0.0.1:445", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "smb", Reason: "x"},
		{Kind: model.KindHost, Target: "10.0.0.1:139", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "smb", Reason: "y"},
	}
	var buf bytes.Buffer
	_ = Render(&buf, fs, nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	if strings.Contains(out, "── hosts") {
		t.Error("a single-kind tier must not print a redundant kind sub-header")
	}
}

func TestEmptyFindingsShowsCleanMessage(t *testing.T) {
	var buf bytes.Buffer
	_ = Render(&buf, nil, nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	if !strings.Contains(out, "No findings matched") {
		t.Errorf("expected the no-findings message, got:\n%s", out)
	}
}

func TestWarningsSectionRenders(t *testing.T) {
	var buf bytes.Buffer
	_ = Render(&buf, nil, nil, []string{"input looked truncated"}, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	if !strings.Contains(out, "WARNINGS") || !strings.Contains(out, "input looked truncated") {
		t.Errorf("expected a warnings section with the warning text, got:\n%s", out)
	}
}

func TestJSONModeUnaffectedByTextRedesign(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, sampleFindings(), nil, []string{"w1"}, []string{"scan.xml"}, Options{JSON: true})
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	var decoded struct {
		Summary  map[string]int  `json:"summary"`
		Findings []model.Finding `json:"findings"`
		Warnings []string        `json:"warnings"`
		Sources  []string        `json:"sources"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON output did not decode: %v\nraw: %s", err, buf.String())
	}
	if decoded.Summary["HIGH"] != 2 {
		t.Errorf("expected 2 HIGH in summary, got %d", decoded.Summary["HIGH"])
	}
	if len(decoded.Findings) != 4 {
		t.Errorf("expected 4 findings, got %d", len(decoded.Findings))
	}
	if strings.ContainsRune(buf.String(), '\x1b') {
		t.Error("JSON output must never contain ANSI escapes")
	}
}

func TestSectionBannerRespectsWidthBounds(t *testing.T) {
	for _, w := range []int{minWidth, DefaultWidth, maxWidth} {
		b := sectionBanner("HIGH — act now (3)", w)
		if n := len([]rune(b)); n < w-2 || n > w+2 {
			t.Errorf("width %d: banner length %d is not close to requested width", w, n)
		}
		if !strings.HasPrefix(b, "╔══╣ ") || !strings.HasSuffix(b, "╗") {
			t.Errorf("banner missing expected box-drawing frame: %q", b)
		}
	}
}

func TestSectionBannerNeverPanicsOnLongTitle(t *testing.T) {
	// A title longer than the available width must degrade gracefully
	// (no negative repeat count / panic), even if the result overflows width.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("sectionBanner panicked: %v", r)
		}
	}()
	b := sectionBanner("WARNINGS — a very long title that exceeds the whole terminal width by a lot (999)", minWidth)
	if b == "" {
		t.Error("expected a non-empty banner even for an oversized title")
	}
}

func TestTargetColumnTruncatesVeryLongTargets(t *testing.T) {
	longTarget := "http://target.com/" + strings.Repeat("a", 200)
	fs := []model.Finding{
		{Kind: model.KindPath, Target: longTarget, Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "x", Reason: "r"},
		{Kind: model.KindPath, Target: "http://t/short", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "x", Reason: "r"},
	}
	var buf bytes.Buffer
	_ = Render(&buf, fs, nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	if strings.Contains(out, strings.Repeat("a", 200)) {
		t.Error("an extremely long target must be truncated, not printed in full and breaking alignment")
	}
}

func TestTerminalWidthFallsBackWhenNil(t *testing.T) {
	if w := TerminalWidth(nil); w != DefaultWidth {
		t.Errorf("expected DefaultWidth for a nil file, got %d", w)
	}
}

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

func TestToolSectionsAppearInOrder(t *testing.T) {
	var buf bytes.Buffer
	_ = Render(&buf, sampleFindings(), nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()

	nmapIdx := strings.Index(out, "nmap · hosts & services")
	ffufIdx := strings.Index(out, "ffuf · discovered content")
	subsIdx := strings.Index(out, "subdomains · enumerated names")
	if nmapIdx < 0 || ffufIdx < 0 || subsIdx < 0 {
		t.Fatalf("missing a tool section banner; output:\n%s", out)
	}
	if !(nmapIdx < ffufIdx && ffufIdx < subsIdx) {
		t.Error("tool sections must appear nmap, then ffuf, then subdomains")
	}
}

func TestToolSectionOmittedWhenToolHasNoFindings(t *testing.T) {
	// An ffuf-only result set must print the ffuf section and nothing for the
	// other two tools.
	fs := []model.Finding{
		{Kind: model.KindPath, Target: "http://t/.git", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "path-git", Reason: ".git exposed"},
	}
	var buf bytes.Buffer
	_ = Render(&buf, fs, nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	if !strings.Contains(out, "ffuf · discovered content") {
		t.Errorf("expected the ffuf section, got:\n%s", out)
	}
	if strings.Contains(out, "nmap · hosts & services") || strings.Contains(out, "subdomains · enumerated names") {
		t.Error("sections for tools with no findings must not be printed")
	}
}

func TestNativeColumnHeadersPresent(t *testing.T) {
	var buf bytes.Buffer
	_ = Render(&buf, sampleFindings(), nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	// Each tool section carries its own native-style column header.
	for _, want := range []string{"HOST:PORT", "SERVICE", "STATUS", "WORDS", "SUBDOMAIN", "RESOLVES TO"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected native column header %q in output:\n%s", want, out)
		}
	}
}

func TestSeverityOrderedWithinToolSection(t *testing.T) {
	// Within one tool's section the higher-severity row must come first, so the
	// must-check item sits at the top. This mirrors production, where Evaluate
	// sorts findings HIGH-first before they reach the renderer.
	fs := []model.Finding{
		{Kind: model.KindHost, Target: "10.0.0.1:135", Severity: model.SevMedium, SevLabel: "MED", RuleID: "msrpc", Reason: "medium thing"},
		{Kind: model.KindHost, Target: "10.0.0.1:445", Severity: model.SevHigh, SevLabel: "HIGH", RuleID: "smb", Reason: "high thing"},
	}
	model.SortFindings(fs)
	var buf bytes.Buffer
	_ = Render(&buf, fs, nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	hi := strings.Index(out, "high thing")
	med := strings.Index(out, "medium thing")
	if hi < 0 || med < 0 || hi > med {
		t.Errorf("HIGH finding must render before MED within a tool section; out:\n%s", out)
	}
}

func TestReasonLineRendersUnderFinding(t *testing.T) {
	var buf bytes.Buffer
	_ = Render(&buf, sampleFindings(), nil, nil, nil, Options{NoColor: true, Width: DefaultWidth})
	out := buf.String()
	// The "why it matters" note is rendered on its own connector line.
	if !strings.Contains(out, "└─ SMB exposed") {
		t.Errorf("expected a connector-prefixed reason line, got:\n%s", out)
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

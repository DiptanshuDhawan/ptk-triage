package orchestrator

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ptk/internal/parser/nmap"
)

// fakeRunner simulates tool execution: it records each command and, for
// nmap/ffuf/subfinder, writes canned output to the file named by the relevant
// output flag — so the flow's downstream stages (parsing nmap.xml to find web
// targets, collecting artifacts) exercise real code against realistic files.
type fakeRunner struct {
	nmapXML  string
	ffufJSON string
	subList  string
	calls    []string
}

func (f *fakeRunner) Run(_ context.Context, bin string, args []string, w io.Writer) error {
	f.calls = append(f.calls, filepath.Base(bin)+" "+strings.Join(args, " "))
	base := strings.ToLower(filepath.Base(bin))
	switch {
	case strings.Contains(base, "nmap"):
		if p := argAfter(args, "-oX"); p != "" && f.nmapXML != "" {
			_ = os.WriteFile(p, []byte(f.nmapXML), 0o644)
		}
	case strings.Contains(base, "ffuf"):
		if p := argAfter(args, "-o"); p != "" && f.ffufJSON != "" {
			_ = os.WriteFile(p, []byte(f.ffufJSON), 0o644)
		}
	case strings.Contains(base, "subfinder"):
		if p := argAfter(args, "-o"); p != "" {
			_ = os.WriteFile(p, []byte(f.subList), 0o644)
		}
	}
	return nil
}

// argAfter returns the token following flag, or "" if absent. Matches the flag
// token exactly so "-o" does not match "-of".
func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

const cannedNmapXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Apache Tomcat"/></port>
    </ports>
  </host>
</nmaprun>`

const cannedFfufJSON = `{"results":[{"input":{"FUZZ":".git/config"},"status":200,"length":92,"url":"http://10.0.0.1:8080/.git/config"}]}`

// allFound builds a tool status map with every tool present at a fake path.
func allFound() map[string]ToolStatus {
	m := map[string]ToolStatus{}
	for _, tool := range DefaultTools() {
		m[tool.Key] = ToolStatus{Tool: tool, Path: "/fake/" + tool.Key, Found: true}
	}
	return m
}

func newTestFlow(tools map[string]ToolStatus, runner Runner) *Flow {
	return &Flow{
		Tools:  tools,
		Runner: runner,
		Resolver: fakeResolver{
			addrs: map[string][]string{
				"target.com":     {"10.0.0.1"},
				"www.target.com": {"10.0.0.1"},
				"dev.target.com": {"10.0.0.1"},
			},
		},
		Prober: fakeProber{up: map[string]int{}},
		Log:    io.Discard,
	}
}

func TestFlowDomainFullRun(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{
		nmapXML:  cannedNmapXML,
		ffufJSON: cannedFfufJSON,
		subList:  "www.target.com\ndev.target.com\n",
	}
	flow := newTestFlow(allFound(), runner)

	// A wordlist must resolve for the ffuf stage; point it at a real temp file.
	wl := filepath.Join(dir, "wl.txt")
	os.WriteFile(wl, []byte("admin\n.git/config\n"), 0o644)

	res, err := flow.Run(context.Background(), Target{Raw: "target.com", Kind: KindDomain}, Options{
		OutDir:   dir,
		Wordlist: wl,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// subs_resolved.csv, nmap.xml, and at least one ffuf_*.json must exist.
	mustExist(t, filepath.Join(dir, fileSubsCSV))
	mustExist(t, filepath.Join(dir, fileNmapXML))

	ffufs, _ := filepath.Glob(filepath.Join(dir, "ffuf_*.json"))
	if len(ffufs) == 0 {
		t.Error("expected at least one ffuf output file")
	}

	// nmap must have been invoked against the resolved IP (10.0.0.1), not the
	// bare domain, proving the resolve stage fed the scan stage.
	var sawNmapWithIP bool
	for _, c := range runner.calls {
		if strings.Contains(c, "nmap") && strings.Contains(c, "10.0.0.1") {
			sawNmapWithIP = true
		}
	}
	if !sawNmapWithIP {
		t.Errorf("nmap was not run against the resolved IP; calls: %v", runner.calls)
	}

	// ffuf must have targeted the web service nmap reported (8080), proving the
	// nmap stage fed the ffuf stage.
	var sawFfuf8080 bool
	for _, c := range runner.calls {
		if strings.Contains(c, "ffuf") && strings.Contains(c, ":8080/FUZZ") {
			sawFfuf8080 = true
		}
	}
	if !sawFfuf8080 {
		t.Errorf("ffuf was not run against the discovered 8080 web service; calls: %v", runner.calls)
	}

	assertRan(t, res, "subfinder", "resolve", "nmap", "ffuf")
}

func TestFlowIPTargetSkipsSubsWithWarning(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{nmapXML: cannedNmapXML, ffufJSON: cannedFfufJSON}
	flow := newTestFlow(allFound(), runner)
	wl := filepath.Join(dir, "wl.txt")
	os.WriteFile(wl, []byte("admin\n"), 0o644)

	res, err := flow.Run(context.Background(), Target{Raw: "10.0.0.1", Kind: KindIP}, Options{OutDir: dir, Wordlist: wl})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	// No subfinder call for an IP target.
	for _, c := range runner.calls {
		if strings.Contains(c, "subfinder") {
			t.Errorf("subfinder must not run for an IP target; calls: %v", runner.calls)
		}
	}
	// nmap must have been run against the IP directly.
	mustExist(t, filepath.Join(dir, fileNmapXML))
	if !hasWarningContaining(res, "not a domain") {
		t.Errorf("expected a 'not a domain' warning, got %v", res.Warnings)
	}
}

func TestFlowMissingNmapWarnsAndSkips(t *testing.T) {
	dir := t.TempDir()
	tools := allFound()
	delete(tools, "nmap")
	tools["nmap"] = ToolStatus{Tool: toolByKey("nmap"), Found: false}
	runner := &fakeRunner{ffufJSON: cannedFfufJSON}
	flow := newTestFlow(tools, runner)
	// Make the prober mark the target up so ffuf's fallback path triggers.
	flow.Prober = fakeProber{up: map[string]int{"10.0.0.1": 200}, scheme: "http"}
	wl := filepath.Join(dir, "wl.txt")
	os.WriteFile(wl, []byte("admin\n"), 0o644)

	res, err := flow.Run(context.Background(), Target{Raw: "10.0.0.1", Kind: KindIP}, Options{OutDir: dir, Wordlist: wl})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if fileExists(filepath.Join(dir, fileNmapXML)) {
		t.Error("nmap.xml must not exist when nmap is missing")
	}
	if !hasWarningContaining(res, "nmap not found") {
		t.Errorf("expected 'nmap not found' warning, got %v", res.Warnings)
	}
	// ffuf fallback: with no nmap results, it should probe the target and fuzz it.
	var sawFfuf bool
	for _, c := range runner.calls {
		if strings.Contains(c, "ffuf") {
			sawFfuf = true
		}
	}
	if !sawFfuf {
		t.Errorf("expected ffuf fallback to fuzz the probed target; calls: %v", runner.calls)
	}
}

func TestFlowSkipFlags(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{nmapXML: cannedNmapXML}
	flow := newTestFlow(allFound(), runner)

	res, err := flow.Run(context.Background(), Target{Raw: "target.com", Kind: KindDomain}, Options{
		OutDir:   dir,
		SkipSubs: true,
		SkipFfuf: true,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	for _, c := range runner.calls {
		if strings.Contains(c, "subfinder") {
			t.Error("subfinder must not run with --skip-subs")
		}
		if strings.Contains(c, "ffuf") {
			t.Error("ffuf must not run with --skip-ffuf")
		}
	}
	if !hasWarningContaining(res, "ffuf stage skipped") {
		t.Errorf("expected ffuf skip warning, got %v", res.Warnings)
	}
}

func TestFlowMissingWordlistSkipsFfuf(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{nmapXML: cannedNmapXML}
	flow := newTestFlow(allFound(), runner)

	// No wordlist given and (on this machine) no default exists.
	res, err := flow.Run(context.Background(), Target{Raw: "10.0.0.1", Kind: KindIP}, Options{OutDir: dir})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	for _, c := range runner.calls {
		if strings.Contains(c, "ffuf") {
			t.Error("ffuf must not run without a wordlist")
		}
	}
	if !hasWarningContaining(res, "no ffuf wordlist") {
		t.Errorf("expected wordlist warning, got %v", res.Warnings)
	}
}

func TestFlowProducedNmapParsesToWebTargets(t *testing.T) {
	// End-to-end sanity: the canned nmap XML the fake runner writes must parse
	// back into the 8080 web service that drives ffuf — i.e. the artifact the
	// orchestrator produces is one the real pipeline understands.
	dir := t.TempDir()
	runner := &fakeRunner{nmapXML: cannedNmapXML, ffufJSON: cannedFfufJSON}
	flow := newTestFlow(allFound(), runner)
	wl := filepath.Join(dir, "wl.txt")
	os.WriteFile(wl, []byte("x\n"), 0o644)

	if _, err := flow.Run(context.Background(), Target{Raw: "10.0.0.1", Kind: KindIP}, Options{OutDir: dir, Wordlist: wl}); err != nil {
		t.Fatal(err)
	}
	pr, err := nmap.ParseFile(filepath.Join(dir, fileNmapXML))
	if err != nil {
		t.Fatal(err)
	}
	wts := WebTargets(pr.Items)
	if len(wts) != 1 || wts[0].Port != 8080 {
		t.Errorf("expected one web target on 8080, got %+v", wts)
	}
}

// --- helpers ---------------------------------------------------------------

func mustExist(t *testing.T, path string) {
	t.Helper()
	if !fileExists(path) {
		t.Errorf("expected file to exist: %s", path)
	}
}

func hasWarningContaining(res Result, sub string) bool {
	for _, w := range res.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func assertRan(t *testing.T, res Result, stages ...string) {
	t.Helper()
	for _, s := range stages {
		found := false
		for _, r := range res.Ran {
			if r == s {
				found = true
			}
		}
		if !found {
			t.Errorf("expected stage %q to have run; ran: %v", s, res.Ran)
		}
	}
}

func toolByKey(key string) Tool {
	for _, tool := range DefaultTools() {
		if tool.Key == key {
			return tool
		}
	}
	return Tool{Key: key}
}

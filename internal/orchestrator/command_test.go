package orchestrator

import (
	"reflect"
	"testing"

	"ptk/internal/model"
)

func TestSubfinderArgs(t *testing.T) {
	got := SubfinderArgs("target.com", "/o/subfinder.txt")
	want := []string{"-d", "target.com", "-silent", "-o", "/o/subfinder.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SubfinderArgs = %v, want %v", got, want)
	}
}

func TestNmapArgsDefault(t *testing.T) {
	got := NmapArgs(nil, "/o/nmap.xml", []string{"1.2.3.4"})
	want := []string{"-sT", "-sV", "-sC", "--top-ports", "1000", "-oX", "/o/nmap.xml", "1.2.3.4"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NmapArgs(default) = %v, want %v", got, want)
	}
}

func TestNmapArgsOverrideReplacesDefaultsButKeepsOutputAndTargets(t *testing.T) {
	got := NmapArgs([]string{"-sS", "-p-"}, "/o/nmap.xml", []string{"h1", "h2"})
	want := []string{"-sS", "-p-", "-oX", "/o/nmap.xml", "h1", "h2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NmapArgs(override) = %v, want %v", got, want)
	}
}

func TestFfufArgs(t *testing.T) {
	got := FfufArgs("wl.txt", "http://t/FUZZ", "/o/ffuf.json", nil)
	want := []string{"-w", "wl.txt", "-u", "http://t/FUZZ", "-o", "/o/ffuf.json", "-of", "json", "-s"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FfufArgs = %v, want %v", got, want)
	}
}

func TestFfufArgsExtraInsertedBeforeOutputFlags(t *testing.T) {
	got := FfufArgs("wl.txt", "http://t/FUZZ", "/o/ffuf.json", []string{"-mc", "all"})
	want := []string{"-w", "wl.txt", "-u", "http://t/FUZZ", "-mc", "all", "-o", "/o/ffuf.json", "-of", "json", "-s"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FfufArgs(extra) = %v, want %v", got, want)
	}
}

func TestWebTargetsExtractionAndScheme(t *testing.T) {
	items := []model.Item{
		{Kind: model.KindHost, Address: "10.0.0.1", Host: "web.t", Port: 80, Service: "http"},
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 8443, Service: "https"},
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 8080, Service: "tcpwrapped"}, // port fallback
		// Non-web services that merely contain "http"/rpc — must be excluded.
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 593, Service: "ncacn_http", Product: "RPC over HTTP"},
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 5985, Service: "http", Product: "Microsoft HTTPAPI httpd"},
		// A non-host item must be ignored.
		{Kind: model.KindPath, Path: "admin"},
	}
	got := WebTargets(items)

	urls := map[string]bool{}
	for _, wt := range got {
		urls[wt.URL] = true
	}
	if !urls["http://web.t:80"] {
		t.Error("expected http://web.t:80 (hostname preferred over address)")
	}
	if !urls["https://10.0.0.1:8443"] {
		t.Error("expected https on 8443")
	}
	if !urls["http://10.0.0.1:8080"] {
		t.Error("expected 8080 via port fallback on tcpwrapped")
	}
	if urls["http://10.0.0.1:593"] || urls["https://10.0.0.1:593"] {
		t.Error("RPC-over-HTTP (593) must not be treated as a web target")
	}
	for u := range urls {
		if u == "http://10.0.0.1:5985" || u == "https://10.0.0.1:5985" {
			t.Error("Windows HTTPAPI (5985) must not be treated as a web target")
		}
	}
}

func TestWebTargetsDedupe(t *testing.T) {
	items := []model.Item{
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 80, Service: "http"},
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 80, Service: "http"},
	}
	if got := WebTargets(items); len(got) != 1 {
		t.Errorf("expected dedupe to 1 target, got %d", len(got))
	}
}

func TestWebTargetFuzzURLAndOutName(t *testing.T) {
	wt := WebTarget{URL: "https://10.0.0.5:8443", Host: "10.0.0.5", Port: 8443}
	if wt.FuzzURL() != "https://10.0.0.5:8443/FUZZ" {
		t.Errorf("FuzzURL = %q", wt.FuzzURL())
	}
	if wt.FfufOutName() != "ffuf_10.0.0.5_8443.json" {
		t.Errorf("FfufOutName = %q", wt.FfufOutName())
	}
}

func TestFfufOutNameSanitizesHostname(t *testing.T) {
	wt := WebTarget{URL: "http://a/b:80", Host: "dev.target.com", Port: 80}
	if wt.FfufOutName() != "ffuf_dev.target.com_80.json" {
		t.Errorf("FfufOutName = %q", wt.FfufOutName())
	}
}

func TestFindWordlist(t *testing.T) {
	// Explicit path that exists.
	if wl, ok := FindWordlist("/my/list.txt", func(p string) bool { return p == "/my/list.txt" }); !ok || wl != "/my/list.txt" {
		t.Errorf("explicit existing wordlist: got (%q,%v)", wl, ok)
	}
	// Explicit path that does not exist -> not found (do not silently fall back).
	if wl, ok := FindWordlist("/missing.txt", func(string) bool { return false }); ok || wl != "" {
		t.Errorf("explicit missing wordlist should fail, got (%q,%v)", wl, ok)
	}
	// No explicit: pick the first default that exists.
	defaults := DefaultWordlists()
	if len(defaults) < 2 {
		t.Fatal("expected multiple default wordlist candidates")
	}
	exists := func(p string) bool { return p == defaults[1] }
	if wl, ok := FindWordlist("", exists); !ok || wl != defaults[1] {
		t.Errorf("auto-detect wordlist: got (%q,%v), want %q", wl, ok, defaults[1])
	}
	// None exist.
	if _, ok := FindWordlist("", func(string) bool { return false }); ok {
		t.Error("expected no wordlist when none exist")
	}
}

func TestValidateURL(t *testing.T) {
	good := []string{"http://10.0.0.1:80", "https://dev.target.com:8443"}
	bad := []string{"ftp://x", "", "http://", "notaurl"}
	for _, g := range good {
		if !validateURL(g) {
			t.Errorf("expected %q to be valid", g)
		}
	}
	for _, b := range bad {
		if validateURL(b) {
			t.Errorf("expected %q to be invalid", b)
		}
	}
}

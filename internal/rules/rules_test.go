package rules

import (
	"strings"
	"testing"

	"ptk/internal/model"
)

// loadDefault loads the embedded ruleset for engine tests.
func loadDefault(t *testing.T) *RuleSet {
	t.Helper()
	rs, warns, err := Load("")
	if err != nil {
		t.Fatalf("loading default rules: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("default ruleset has compile warnings (should be clean): %v", warns)
	}
	return rs
}

func findingsWithRule(fs []model.Finding, ruleID string) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func TestDefaultRulesetLoadsClean(t *testing.T) {
	rs := loadDefault(t)
	if len(rs.Patterns) == 0 {
		t.Fatal("expected pattern rules in default set")
	}
	// Every pattern rule must have a non-empty reason — never flag without why.
	for _, p := range rs.Patterns {
		if strings.TrimSpace(p.Reason) == "" {
			t.Errorf("rule %q has no reason string", p.ID)
		}
		if p.re == nil {
			t.Errorf("rule %q failed to compile", p.ID)
		}
	}
}

func TestHTTPAPINotFlaggedNonstandard(t *testing.T) {
	rs := loadDefault(t)
	// Regression: Microsoft HTTPAPI (WinRM/WSMan stack) on 5985/47001 was wrongly
	// flagged as "HTTP on non-standard port". It must NOT be.
	items := []model.Item{
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 5985, Service: "http", Product: "Microsoft HTTPAPI httpd", Version: "2.0"},
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 47001, Service: "http", Product: "Microsoft HTTPAPI httpd", Version: "2.0"},
	}
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "nonstandard-http")) != 0 {
		t.Error("Microsoft HTTPAPI must not be flagged as nonstandard HTTP")
	}
	// And it must not be flagged as an old version (2.0 is a protocol version).
	if len(findingsWithRule(fs, "old-version")) != 0 {
		t.Error("HTTPAPI 2.0 must not be flagged old-version")
	}
}

func TestRPCOverHTTPNotFlaggedWeb(t *testing.T) {
	rs := loadDefault(t)
	// Regression: 593 ncacn_http (RPC over HTTP) was wrongly flagged as a web port.
	items := []model.Item{
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 593, Service: "ncacn_http", Product: "Microsoft Windows RPC over HTTP", Version: "1.0"},
	}
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "nonstandard-http")) != 0 {
		t.Error("RPC-over-HTTP (ncacn_http) must not be flagged as a web port")
	}
	if len(findingsWithRule(fs, "old-version")) != 0 {
		t.Error("RPC over HTTP 1.0 must not be flagged old-version")
	}
}

func TestOldVersionRequiresFullVersion(t *testing.T) {
	rs := loadDefault(t)
	// Real aged software with a full x.y.z version SHOULD flag.
	hit := []model.Item{{Kind: model.KindHost, Port: 80, Service: "http", Product: "Apache httpd", Version: "2.2.15", Banner: "Apache httpd 2.2.15"}}
	if len(findingsWithRule(rs.Evaluate(hit), "old-version")) == 0 {
		t.Error("Apache 2.2.15 should flag old-version")
	}
	// A bare protocol-style "2.0" should NOT.
	miss := []model.Item{{Kind: model.KindHost, Port: 5985, Service: "http", Product: "Microsoft HTTPAPI httpd", Version: "2.0", Banner: "Microsoft HTTPAPI httpd 2.0"}}
	if len(findingsWithRule(rs.Evaluate(miss), "old-version")) != 0 {
		t.Error("bare 2.0 must not flag old-version")
	}
}

func TestSMBSigningVariantsFlagged(t *testing.T) {
	rs := loadDefault(t)
	variants := []string{
		"smb2-security-mode: Message signing enabled but not required",
		"smb-security-mode: message_signing: disabled (dangerous, but default)",
		"signing not required",
	}
	for _, v := range variants {
		items := []model.Item{{Kind: model.KindHost, Port: 445, Service: "microsoft-ds", Scripts: v}}
		if len(findingsWithRule(rs.Evaluate(items), "nse-smb-signing")) == 0 {
			t.Errorf("SMB signing variant not flagged: %q", v)
		}
	}
}

func TestNotNmapXMLEngineStillRuns(t *testing.T) {
	rs := loadDefault(t)
	// A size outlier among many identical responses is flagged; the lone
	// baseline items are not.
	var items []model.Item
	for i := 0; i < 20; i++ {
		items = append(items, model.Item{Kind: model.KindPath, Path: "x", Status: 200, Length: 4096})
	}
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "size-outlier")) != 0 {
		t.Error("uniform responses must not produce outliers")
	}
}

func TestSMBFlaggedHigh(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{{
		Kind: model.KindHost, Address: "10.10.10.5", Port: 445,
		Protocol: "tcp", Service: "microsoft-ds",
	}}
	fs := rs.Evaluate(items)
	smb := findingsWithRule(fs, "smb")
	if len(smb) != 1 {
		t.Fatalf("expected 1 smb finding, got %d", len(smb))
	}
	if smb[0].Severity != model.SevHigh {
		t.Errorf("SMB should be HIGH, got %s", smb[0].Severity)
	}
	if smb[0].Reason == "" {
		t.Error("finding has no reason")
	}
}

func TestNSEAnonymousFlagged(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{{
		Kind: model.KindHost, Address: "10.10.10.5", Port: 21, Service: "ftp",
		Scripts: "ftp-anon: Anonymous FTP login allowed",
	}}
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "nse-anonymous")) == 0 {
		t.Error("expected nse-anonymous finding from script output")
	}
}

func TestNonStandardHTTPBuiltin(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{{
		Kind: model.KindHost, Address: "10.10.10.5", Port: 8443, Service: "http",
	}}
	fs := rs.Evaluate(items)
	// 8443 is in standard_http_ports by default -> should NOT flag nonstandard.
	if len(findingsWithRule(fs, "nonstandard-http")) != 0 {
		t.Error("8443 is a standard http port, should not be flagged nonstandard")
	}

	items[0].Port = 7001
	fs = rs.Evaluate(items)
	if len(findingsWithRule(fs, "nonstandard-http")) == 0 {
		t.Error("http on 7001 should be flagged nonstandard")
	}
}

func TestUnknownServiceBuiltin(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{{
		Kind: model.KindHost, Address: "10.10.10.5", Port: 9999, Service: "tcpwrapped",
	}}
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "unknown-service")) == 0 {
		t.Error("tcpwrapped should be flagged as unknown service")
	}
}

func TestFFUFSensitivePaths(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{
		{Kind: model.KindPath, URL: "http://t/.git/config", Path: ".git/config", Status: 200, Length: 92},
		{Kind: model.KindPath, URL: "http://t/.env", Path: ".env", Status: 200, Length: 120},
		{Kind: model.KindPath, URL: "http://t/backup.zip", Path: "backup.zip", Status: 200, Length: 90000},
	}
	fs := rs.Evaluate(items)
	for _, rule := range []string{"path-vcs", "path-env", "path-backup"} {
		if len(findingsWithRule(fs, rule)) == 0 {
			t.Errorf("expected %s to fire", rule)
		}
	}
}

func TestSizeOutlier(t *testing.T) {
	rs := loadDefault(t)
	// Build a baseline of 20 identical responses plus one outlier.
	var items []model.Item
	for i := 0; i < 20; i++ {
		items = append(items, model.Item{Kind: model.KindPath, Path: "p", Status: 404, Length: 500})
	}
	items = append(items, model.Item{Kind: model.KindPath, URL: "http://t/hit", Path: "hit", Status: 200, Length: 4000})
	fs := rs.Evaluate(items)
	out := findingsWithRule(fs, "size-outlier")
	if len(out) == 0 {
		t.Fatal("expected a size-outlier finding")
	}
	// Baseline of 500 should not itself be flagged.
	for _, f := range out {
		if strings.Contains(f.Target, "404") {
			t.Error("baseline responses should not be outliers")
		}
	}
}

func TestSizeOutlierSuppressedOnSmallSet(t *testing.T) {
	rs := loadDefault(t)
	// Only 3 paths: below size_outlier_min_set, so no baseline judgement.
	items := []model.Item{
		{Kind: model.KindPath, Path: "a", Length: 100},
		{Kind: model.KindPath, Path: "b", Length: 100},
		{Kind: model.KindPath, Path: "c", Length: 9000},
	}
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "size-outlier")) != 0 {
		t.Error("size-outlier should be suppressed on a tiny result set")
	}
}

func TestDanglingCNAMEHigh(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{{
		Kind: model.KindSub, Name: "old.target.com",
		CNAME: "gone.s3.amazonaws.com", Resolved: false,
	}}
	fs := rs.Evaluate(items)
	d := findingsWithRule(fs, "dangling-cname")
	if len(d) == 0 {
		t.Fatal("expected dangling-cname finding")
	}
	if d[0].Severity != model.SevHigh {
		t.Errorf("dangling CNAME must be HIGH, got %s", d[0].Severity)
	}
}

func TestOffRangeIP(t *testing.T) {
	rs := loadDefault(t)
	rs.Builtins.PrimaryCIDRs = []string{"203.0.113.0/24"}
	rs.primaryNets = nil
	rs.compile() // re-parse CIDRs

	items := []model.Item{
		{Kind: model.KindSub, Name: "in.target.com", Address: "203.0.113.5", Resolved: true, HTTPUp: true},
		{Kind: model.KindSub, Name: "out.target.com", Address: "8.8.8.8", Resolved: true, HTTPUp: true},
	}
	fs := rs.Evaluate(items)
	off := findingsWithRule(fs, "offrange-ip")
	if len(off) != 1 || off[0].Target != "out.target.com" {
		t.Errorf("expected only out.target.com off-range, got %+v", off)
	}
}

func TestSeverityFilter(t *testing.T) {
	fs := []model.Finding{
		{Severity: model.SevHigh, SevLabel: "HIGH"},
		{Severity: model.SevMedium, SevLabel: "MED"},
		{Severity: model.SevLow, SevLabel: "LOW"},
		{Severity: model.SevInfo, SevLabel: "INFO"},
	}
	if got := Filter(fs, model.SevHigh); len(got) != 1 {
		t.Errorf("only-high should keep 1, got %d", len(got))
	}
	if got := Filter(fs, model.SevMedium); len(got) != 2 {
		t.Errorf("only-high-medium should keep 2, got %d", len(got))
	}
}

func TestComboBoost(t *testing.T) {
	rs := loadDefault(t)
	// Same target hit by a high-value service rule and an outdated-version rule.
	fs := []model.Finding{
		{Target: "10.0.0.1:445", RuleID: "smb", Severity: model.SevMedium, SevLabel: "MED"},
		{Target: "10.0.0.1:445", RuleID: "outdated-version", Severity: model.SevLow, SevLabel: "LOW"},
	}
	applyCombos(fs)
	for _, f := range fs {
		if f.Severity < model.SevMedium {
			t.Errorf("combo should have boosted %s", f.RuleID)
		}
	}
	_ = rs
}

func TestReasonsNeverEmpty(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{
		{Kind: model.KindHost, Address: "1.1.1.1", Port: 445, Service: "microsoft-ds"},
		{Kind: model.KindPath, Path: ".env", Status: 200, Length: 10},
		{Kind: model.KindSub, Name: "x.y.com", CNAME: "gone.example", Resolved: false},
	}
	for _, f := range rs.Evaluate(items) {
		if strings.TrimSpace(f.Reason) == "" {
			t.Errorf("finding for rule %q has empty reason", f.RuleID)
		}
	}
}

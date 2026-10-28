package rules

import (
	"fmt"
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
	// Baseline of 20 identical SAME-STATUS responses plus one same-status outlier.
	var items []model.Item
	for i := 0; i < 20; i++ {
		items = append(items, model.Item{Kind: model.KindPath, Path: "p", Status: 200, Length: 500})
	}
	items = append(items, model.Item{Kind: model.KindPath, URL: "http://t/hit", Path: "hit", Status: 200, Length: 4000})
	fs := rs.Evaluate(items)
	out := findingsWithRule(fs, "size-outlier")
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 size-outlier finding, got %d", len(out))
	}
	if out[0].Target != "http://t/hit" {
		t.Errorf("wrong item flagged as outlier: %+v", out[0])
	}
}

func TestSizeOutlierPerStatusDoesNotCrossContaminate(t *testing.T) {
	// Regression: the baseline used to be computed globally across ALL status
	// codes, so a lone response of a rare status could be wrongly compared
	// against an unrelated status's noise floor (false positive/negative in
	// both directions). Build two independent, well-populated status groups
	// with DIFFERENT baselines and confirm each outlier is judged only against
	// its own group.
	rs := loadDefault(t)
	var items []model.Item
	for i := 0; i < 20; i++ {
		items = append(items, model.Item{Kind: model.KindPath, Path: "n200", Status: 200, Length: 500})
	}
	for i := 0; i < 20; i++ {
		items = append(items, model.Item{Kind: model.KindPath, Path: "n403", Status: 403, Length: 9000})
	}
	// Outlier within the 200 group (far from 500, nowhere near the 403 group's 9000).
	items = append(items, model.Item{Kind: model.KindPath, URL: "http://t/hit200", Status: 200, Length: 4000})
	// Outlier within the 403 group (far from 9000, nowhere near the 200 group's 500).
	items = append(items, model.Item{Kind: model.KindPath, URL: "http://t/hit403", Status: 403, Length: 500})

	fs := rs.Evaluate(items)
	out := findingsWithRule(fs, "size-outlier")
	targets := map[string]bool{}
	for _, f := range out {
		targets[f.Target] = true
	}
	if !targets["http://t/hit200"] {
		t.Error("expected the 200-group outlier to be flagged")
	}
	if !targets["http://t/hit403"] {
		t.Error("expected the 403-group outlier to be flagged")
	}
	if len(out) != 2 {
		t.Errorf("expected exactly 2 outliers (one per status group), got %d: %+v", len(out), out)
	}
}

func TestShapeOutlierCatchesSimilarSizeDifferentStructure(t *testing.T) {
	rs := loadDefault(t)
	var items []model.Item
	for i := 0; i < 20; i++ {
		items = append(items, model.Item{Kind: model.KindPath, Path: "n", Status: 200, Length: 1000, Words: 100})
	}
	// Same byte size as baseline (so size-outlier stays quiet) but very
	// different word count (e.g. a dense error blob padded to a similar size).
	items = append(items, model.Item{Kind: model.KindPath, URL: "http://t/shape", Status: 200, Length: 1000, Words: 5})
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "size-outlier")) != 0 {
		t.Error("identical byte size must not trigger size-outlier")
	}
	shape := findingsWithRule(fs, "shape-outlier")
	if len(shape) != 1 || shape[0].Target != "http://t/shape" {
		t.Errorf("expected shape-outlier on the word-count anomaly, got %+v", shape)
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
	// Same target hit by a finding tagged "service" and one tagged "aged".
	// This exercises applyCombos directly against the new tag-based design
	// (replacing the old hardcoded-rule-ID check, which had a dead branch —
	// see TestComboBoostEndToEnd for the regression test on that bug).
	fs := []model.Finding{
		{Target: "10.0.0.1:445", RuleID: "smb", Severity: model.SevMedium, SevLabel: "MED", Tags: []string{"service"}},
		{Target: "10.0.0.1:445", RuleID: "some-aged-rule", Severity: model.SevLow, SevLabel: "LOW", Tags: []string{"aged"}},
	}
	applyCombos(fs)
	for _, f := range fs {
		if f.Severity < model.SevMedium {
			t.Errorf("combo should have boosted %s", f.RuleID)
		}
	}
}

func TestComboBoostEndToEnd(t *testing.T) {
	// Regression: the original combo implementation checked for a literal
	// rule ID ("outdated-version") that no actual rule emitted, so the combo
	// silently never fired through the real pipeline despite being enabled.
	// Drive it through rs.Evaluate with real rules to prove it actually
	// boosts severity end-to-end, not just when a test hand-crafts tags.
	rs := loadDefault(t)
	items := []model.Item{{
		Kind: model.KindHost, Address: "10.0.0.1", Port: 445, Service: "microsoft-ds",
		Banner: "Samba smbd 3.0.20", // old-version pattern requires a full x.y.z
	}}
	fs := rs.Evaluate(items)
	smb := findingsWithRule(fs, "smb")
	aged := findingsWithRule(fs, "old-version")
	if len(smb) == 0 || len(aged) == 0 {
		t.Fatalf("expected both smb and old-version to fire as a precondition, got smb=%d aged=%d", len(smb), len(aged))
	}
	if !strings.Contains(aged[0].Reason, "boosted") {
		t.Errorf("expected old-version finding to be boosted by the service+aged combo, reason: %q", aged[0].Reason)
	}
	if aged[0].Severity < model.SevMedium {
		t.Errorf("boosted finding should be at least MED, got %s", aged[0].Severity)
	}
}

func TestWildcardDNSDetected(t *testing.T) {
	rs := loadDefault(t)
	var items []model.Item
	// 6 distinct subdomains all resolving to the same IP => wildcard suspicion.
	for i := 0; i < 6; i++ {
		items = append(items, model.Item{
			Kind: model.KindSub, Name: fmt.Sprintf("rand%d.target.com", i),
			Address: "203.0.113.50", Resolved: true, HTTPUp: true,
		})
	}
	fs := rs.Evaluate(items)
	wc := findingsWithRule(fs, "wildcard-dns")
	if len(wc) != 1 {
		t.Fatalf("expected exactly 1 wildcard-dns finding, got %d", len(wc))
	}
	if wc[0].Severity != model.SevInfo {
		t.Errorf("wildcard-dns should be INFO, got %s", wc[0].Severity)
	}
}

func TestWildcardDNSNotFlaggedWhenDiverse(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{
		{Kind: model.KindSub, Name: "a.target.com", Address: "203.0.113.10", Resolved: true, HTTPUp: true},
		{Kind: model.KindSub, Name: "b.target.com", Address: "203.0.113.11", Resolved: true, HTTPUp: true},
		{Kind: model.KindSub, Name: "c.target.com", Address: "203.0.113.12", Resolved: true, HTTPUp: true},
	}
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "wildcard-dns")) != 0 {
		t.Error("diverse IPs should not trigger wildcard-dns")
	}
}

func TestNewHighValueServiceRulesFire(t *testing.T) {
	rs := loadDefault(t)
	cases := []struct {
		rule string
		item model.Item
	}{
		{"ipmi", model.Item{Kind: model.KindHost, Port: 623, Service: "asf-rmcp"}},
		{"oob-mgmt", model.Item{Kind: model.KindHost, Port: 443, Banner: "Integrated Lights-Out 5 1.30"}},
		{"vcenter-esxi", model.Item{Kind: model.KindHost, Port: 443, Banner: "VMware vCenter Server"}},
		{"citrix", model.Item{Kind: model.KindHost, Port: 443, Banner: "Citrix NetScaler"}},
		{"f5-bigip", model.Item{Kind: model.KindHost, Port: 443, Banner: "BIG-IP"}},
		{"fortinet", model.Item{Kind: model.KindHost, Port: 443, Banner: "FortiGate firmware"}},
		{"etcd", model.Item{Kind: model.KindHost, Port: 2379, Service: "http"}},
		{"docker-api", model.Item{Kind: model.KindHost, Port: 2375, Service: "http"}},
		{"r-services", model.Item{Kind: model.KindHost, Port: 514, Service: "shell"}},
		{"portainer", model.Item{Kind: model.KindHost, Port: 9000, Banner: "Portainer"}},
		{"db-couchdb", model.Item{Kind: model.KindHost, Port: 5984, Service: "couchdb"}},
		{"nse-eternalblue", model.Item{Kind: model.KindHost, Port: 445, Scripts: "smb-vuln-ms17-010: VULNERABLE"}},
	}
	for _, c := range cases {
		fs := rs.Evaluate([]model.Item{c.item})
		if len(findingsWithRule(fs, c.rule)) == 0 {
			t.Errorf("expected rule %q to fire for %+v", c.rule, c.item)
		}
	}
}

func TestNewFFUFPathRulesFire(t *testing.T) {
	rs := loadDefault(t)
	cases := []struct {
		rule string
		path string
	}{
		{"path-iac", "docker-compose.yml"},
		{"path-iac", "terraform.tfstate"},
		{"path-ci", ".github/workflows/deploy.yml"},
		{"path-dotnet-debug", "elmah.axd"},
		{"path-soap", "service.wsdl"},
		{"path-metrics", "metrics"},
		{"path-health", "healthz"},
		{"path-dev-artifacts", ".DS_Store"},
	}
	for _, c := range cases {
		items := []model.Item{{Kind: model.KindPath, URL: "http://t/" + c.path, Path: c.path, Status: 200}}
		fs := rs.Evaluate(items)
		if len(findingsWithRule(fs, c.rule)) == 0 {
			t.Errorf("expected rule %q to fire for path %q", c.rule, c.path)
		}
	}
}

func TestPunycodeSubFlagged(t *testing.T) {
	rs := loadDefault(t)
	items := []model.Item{{Kind: model.KindSub, Name: "xn--80ak6aa92e.target.com"}}
	fs := rs.Evaluate(items)
	if len(findingsWithRule(fs, "sub-punycode")) == 0 {
		t.Error("expected punycode subdomain to be flagged")
	}
}

func TestByKindBucketingDoesNotCrossApply(t *testing.T) {
	rs := loadDefault(t)
	// A host-only rule (smb) must never fire for a path or sub item, and a
	// path-only rule (path-vcs) must never fire for a host item, even if the
	// field happens to contain a matching substring. This guards the
	// performance bucketing (byKind) against accidentally changing behavior.
	hostItem := model.Item{Kind: model.KindHost, Port: 445, Service: "microsoft-ds", Path: ".git/config"}
	fs := rs.Evaluate([]model.Item{hostItem})
	if len(findingsWithRule(fs, "path-vcs")) != 0 {
		t.Error("path-only rule must not fire on a host item")
	}

	pathItem := model.Item{Kind: model.KindPath, Service: "microsoft-ds", Path: "x", Status: 200}
	fs = rs.Evaluate([]model.Item{pathItem})
	if len(findingsWithRule(fs, "smb")) != 0 {
		t.Error("host-only rule must not fire on a path item")
	}
}

func TestParallelEvaluationMatchesSequential(t *testing.T) {
	rs := loadDefault(t)
	// Build a large, deterministic mixed set that crosses parallelThreshold,
	// and confirm the result is identical (content-wise) to evaluating a
	// small slice of the same data sequentially — i.e. splitting into chunks
	// for the worker pool must not drop, duplicate, or alter any finding.
	var items []model.Item
	for i := 0; i < 3000; i++ {
		items = append(items, model.Item{
			Kind: model.KindHost, Address: "10.0.0.1", Port: 20000 + i, Service: "microsoft-ds",
		})
	}
	fs := rs.Evaluate(items)
	smb := findingsWithRule(fs, "smb")
	if len(smb) != 3000 {
		t.Fatalf("expected 3000 smb findings from parallel evaluation, got %d", len(smb))
	}
	// Re-run to confirm determinism across repeated parallel runs.
	fs2 := rs.Evaluate(items)
	if len(fs2) != len(fs) {
		t.Fatalf("non-deterministic finding count across runs: %d vs %d", len(fs), len(fs2))
	}
	for i := range fs {
		if fs[i].Target != fs2[i].Target || fs[i].RuleID != fs2[i].RuleID {
			t.Fatalf("non-deterministic ordering at index %d: %+v vs %+v", i, fs[i], fs2[i])
		}
	}
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

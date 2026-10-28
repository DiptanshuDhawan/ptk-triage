package orchestrator

import (
	"context"
	"errors"
	"testing"
)

// fakeResolver returns canned A records and CNAMEs per name.
type fakeResolver struct {
	addrs  map[string][]string
	cnames map[string]string
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f.addrs[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cnames[host]; ok {
		return c, nil
	}
	return host, nil // stdlib returns the name itself when there's no CNAME
}

// fakeProber marks specific hosts as HTTP-up.
type fakeProber struct {
	up     map[string]int
	scheme string
}

func (f fakeProber) Probe(_ context.Context, host string) (int, string, bool) {
	if s, ok := f.up[host]; ok {
		sch := f.scheme
		if sch == "" {
			sch = "http"
		}
		return s, sch, true
	}
	return 0, "", false
}

func TestEnrichResolvedAndDangling(t *testing.T) {
	res := fakeResolver{
		addrs: map[string][]string{
			"www.target.com": {"203.0.113.10"},
			"api.target.com": {"203.0.113.11"},
		},
		cnames: map[string]string{
			// Dangling: has a CNAME to a cloud provider but no A record.
			"old.target.com": "old.target.com.s3.amazonaws.com.",
		},
	}
	probe := fakeProber{up: map[string]int{"www.target.com": 200}}

	names := []string{"www.target.com", "api.target.com", "old.target.com"}
	got := Enrich(context.Background(), names, res, probe, 4)

	if len(got) != 3 {
		t.Fatalf("expected 3 results, got %d", len(got))
	}
	// Results are sorted by name: api, old, www.
	byName := map[string]ResolvedSub{}
	for _, r := range got {
		byName[r.Name] = r
	}

	www := byName["www.target.com"]
	if !www.Resolved || len(www.Addrs) != 1 || www.Addrs[0] != "203.0.113.10" {
		t.Errorf("www not resolved correctly: %+v", www)
	}
	if !www.HTTPUp || www.Status != 200 {
		t.Errorf("www HTTP probe not recorded: %+v", www)
	}

	old := byName["old.target.com"]
	if old.Resolved {
		t.Errorf("old.target.com must be unresolved (dangling): %+v", old)
	}
	if old.CNAME != "old.target.com.s3.amazonaws.com" {
		t.Errorf("expected trimmed CNAME, got %q", old.CNAME)
	}
}

func TestResolvedSubCSVLine(t *testing.T) {
	resolved := ResolvedSub{Name: "www.t.com", Addrs: []string{"1.2.3.4"}, Resolved: true, Status: 200, HTTPUp: true}
	if got := resolved.CSVLine(); got != "www.t.com,1.2.3.4,200," {
		t.Errorf("resolved CSVLine = %q", got)
	}
	// Dangling: no IP/status, CNAME present in the 4th column so the subs
	// dangling-CNAME rule can fire when this round-trips through the parser.
	dangling := ResolvedSub{Name: "old.t.com", CNAME: "x.s3.amazonaws.com", Resolved: false}
	if got := dangling.CSVLine(); got != "old.t.com,,,x.s3.amazonaws.com" {
		t.Errorf("dangling CSVLine = %q", got)
	}
	// Resolved host with a benign CNAME: CNAME omitted so it isn't flagged.
	benign := ResolvedSub{Name: "cdn.t.com", Addrs: []string{"5.6.7.8"}, Resolved: true, CNAME: "cdn.cloudfront.net"}
	if got := benign.CSVLine(); got != "cdn.t.com,5.6.7.8,," {
		t.Errorf("benign CSVLine should omit CNAME, got %q", got)
	}
}

func TestUniqueIPs(t *testing.T) {
	subs := []ResolvedSub{
		{Name: "a", Addrs: []string{"10.0.0.2", "10.0.0.1"}},
		{Name: "b", Addrs: []string{"10.0.0.1"}},
		{Name: "c"},
	}
	got := UniqueIPs(subs)
	want := []string{"10.0.0.1", "10.0.0.2"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("UniqueIPs = %v, want %v (sorted, deduped)", got, want)
	}
}

func TestEnrichProbeDisabledWhenProberNil(t *testing.T) {
	res := fakeResolver{addrs: map[string][]string{"www.t.com": {"1.2.3.4"}}}
	got := Enrich(context.Background(), []string{"www.t.com"}, res, nil, 2)
	if got[0].HTTPUp {
		t.Error("HTTPUp must be false when no prober is supplied")
	}
}

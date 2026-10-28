package subs

import (
	"strings"
	"testing"
)

func TestCSVParsing(t *testing.T) {
	in := `# comment
www.target.com,203.0.113.10,200
internal.target.com,10.0.0.5
old.target.com,dangling.s3.amazonaws.com
`
	res := Parse(strings.NewReader(in))
	if len(res.Items) != 3 {
		t.Fatalf("expected 3 subs, got %d: %+v", len(res.Items), res.Items)
	}

	byName := map[string]int{}
	for i, it := range res.Items {
		byName[it.Name] = i
	}

	www := res.Items[byName["www.target.com"]]
	if www.Address != "203.0.113.10" || www.Status != 200 || !www.HTTPUp {
		t.Errorf("www parsed wrong: %+v", www)
	}

	internal := res.Items[byName["internal.target.com"]]
	if internal.Address != "10.0.0.5" || !internal.Resolved {
		t.Errorf("internal parsed wrong: %+v", internal)
	}
	if internal.HTTPUp {
		t.Error("internal has no status, should not be HTTPUp")
	}

	old := res.Items[byName["old.target.com"]]
	if old.CNAME != "dangling.s3.amazonaws.com" {
		t.Errorf("expected CNAME target, got %+v", old)
	}
	if old.Resolved {
		t.Error("CNAME-only host should not be marked resolved")
	}
}

func TestPlainList(t *testing.T) {
	in := "a.example.com\nb.example.com\nnot a hostname at all\nc.example.com\n"
	res := Parse(strings.NewReader(in))
	if len(res.Items) != 3 {
		t.Fatalf("expected 3 hostnames, got %d", len(res.Items))
	}
}

func TestAmassArrowForm(t *testing.T) {
	in := `dev.target.com (FQDN) --> cname_record --> dev.target.com.s3.amazonaws.com (FQDN)
host2.target.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)`
	res := Parse(strings.NewReader(in))
	if len(res.Items) != 2 {
		t.Fatalf("expected 2 items, got %d: %+v", len(res.Items), res.Items)
	}
	byName := map[string]int{}
	for i, it := range res.Items {
		byName[it.Name] = i
	}
	dev := res.Items[byName["dev.target.com"]]
	if dev.CNAME != "dev.target.com.s3.amazonaws.com" {
		t.Errorf("amass cname not parsed: %+v", dev)
	}
	h2 := res.Items[byName["host2.target.com"]]
	if h2.Address != "1.2.3.4" || !h2.Resolved {
		t.Errorf("amass a-record not parsed: %+v", h2)
	}
}

func TestMergeDuplicates(t *testing.T) {
	// Same host appears twice: once as a plain name, once resolved.
	in := "api.target.com\napi.target.com,203.0.113.10,200\n"
	res := Parse(strings.NewReader(in))
	if len(res.Items) != 1 {
		t.Fatalf("expected merge into 1 item, got %d", len(res.Items))
	}
	if res.Items[0].Address != "203.0.113.10" || res.Items[0].Status != 200 {
		t.Errorf("merge did not enrich: %+v", res.Items[0])
	}
}

func TestTabSeparated(t *testing.T) {
	in := "host.target.com\t203.0.113.5\t200\n"
	res := Parse(strings.NewReader(in))
	if len(res.Items) != 1 || res.Items[0].Address != "203.0.113.5" {
		t.Fatalf("tab-separated not parsed: %+v", res.Items)
	}
}

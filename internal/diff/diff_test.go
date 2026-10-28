package diff

import (
	"strings"
	"testing"

	"ptk/internal/model"
)

func TestHostDiff(t *testing.T) {
	old := []model.Item{
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 22, Protocol: "tcp", Service: "ssh", Banner: "OpenSSH 7.2"},
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 80, Protocol: "tcp", Service: "http"},
	}
	new := []model.Item{
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 22, Protocol: "tcp", Service: "ssh", Banner: "OpenSSH 9.6"},
		{Kind: model.KindHost, Address: "10.0.0.1", Port: 445, Protocol: "tcp", Service: "microsoft-ds"},
	}
	r := Compute(old, new)
	a, rm, ch := r.Counts()
	if a != 1 || rm != 1 || ch != 1 {
		t.Fatalf("expected 1 added / 1 removed / 1 changed, got %d/%d/%d", a, rm, ch)
	}
	if r.Added[0].Item.Port != 445 {
		t.Errorf("expected 445 added, got %d", r.Added[0].Item.Port)
	}
	if r.Removed[0].Item.Port != 80 {
		t.Errorf("expected 80 removed, got %d", r.Removed[0].Item.Port)
	}
	if !strings.Contains(r.Changed[0].Detail, "7.2") || !strings.Contains(r.Changed[0].Detail, "9.6") {
		t.Errorf("banner change not described: %q", r.Changed[0].Detail)
	}
}

func TestSubTakeoverTransition(t *testing.T) {
	old := []model.Item{
		{Kind: model.KindSub, Name: "shop.t.com", Address: "1.2.3.4", Resolved: true},
		{Kind: model.KindSub, Name: "app.t.com", CNAME: "app.herokuapp.com", Resolved: false},
	}
	new := []model.Item{
		{Kind: model.KindSub, Name: "shop.t.com", CNAME: "shop.herokuapp.com", Resolved: false},
		{Kind: model.KindSub, Name: "app.t.com", Address: "5.6.7.8", Resolved: true},
	}
	r := Compute(old, new)
	fs := r.ToFindings()

	var newTakeover, closedWindow bool
	var takeoverSev model.Severity
	for _, f := range fs {
		if strings.Contains(f.Reason, "NEW possible subdomain takeover") {
			newTakeover = true
			takeoverSev = f.Severity
		}
		if strings.Contains(f.Reason, "takeover window likely closed") {
			closedWindow = true
		}
	}
	if !newTakeover {
		t.Error("expected a NEW takeover transition for shop.t.com")
	}
	if takeoverSev != model.SevHigh {
		t.Errorf("new takeover must be HIGH, got %s", takeoverSev)
	}
	if !closedWindow {
		t.Error("expected app.t.com to be reported as window closed")
	}
}

func TestPathDiff(t *testing.T) {
	old := []model.Item{{Kind: model.KindPath, URL: "http://t/a", Status: 200, Length: 100}}
	new := []model.Item{{Kind: model.KindPath, URL: "http://t/a", Status: 403, Length: 100}}
	r := Compute(old, new)
	_, _, ch := r.Counts()
	if ch != 1 {
		t.Fatalf("expected 1 changed path, got %d", ch)
	}
	if !strings.Contains(r.Changed[0].Detail, "200 -> 403") {
		t.Errorf("status change not described: %q", r.Changed[0].Detail)
	}
}

func TestNoChange(t *testing.T) {
	items := []model.Item{{Kind: model.KindHost, Address: "10.0.0.1", Port: 22, Protocol: "tcp", Service: "ssh"}}
	r := Compute(items, items)
	a, rm, ch := r.Counts()
	if a != 0 || rm != 0 || ch != 0 {
		t.Errorf("identical scans should produce no diff, got %d/%d/%d", a, rm, ch)
	}
}

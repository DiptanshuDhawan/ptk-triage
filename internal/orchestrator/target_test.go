package orchestrator

import "testing"

func TestClassifyTarget(t *testing.T) {
	cases := []struct {
		in   string
		raw  string
		kind TargetKind
	}{
		{"target.com", "target.com", KindDomain},
		{"sub.dev.target.com", "sub.dev.target.com", KindDomain},
		{"TARGET.COM", "target.com", KindDomain},
		{"http://target.com/some/path", "target.com", KindDomain},
		{"https://target.com:8443/x?y=1", "target.com", KindDomain},
		{"target.com:443", "target.com", KindDomain},
		{"target.com.", "target.com", KindDomain},
		{"  target.com  ", "target.com", KindDomain},
		{"10.10.10.5", "10.10.10.5", KindIP},
		{"10.10.10.5:22", "10.10.10.5", KindIP},
		{"2001:db8::1", "2001:db8::1", KindIP},
		{"10.10.10.0/24", "10.10.10.0/24", KindCIDR},
		{"192.168.0.0/16", "192.168.0.0/16", KindCIDR},
		{"notadomain", "notadomain", KindUnknown}, // single label, no dot
		{"foo.123", "foo.123", KindUnknown},       // numeric TLD
		{"", "", KindUnknown},
	}
	for _, c := range cases {
		got := ClassifyTarget(c.in)
		if got.Kind != c.kind {
			t.Errorf("ClassifyTarget(%q).Kind = %v, want %v", c.in, got.Kind, c.kind)
		}
		if got.Kind != KindUnknown && got.Raw != c.raw {
			t.Errorf("ClassifyTarget(%q).Raw = %q, want %q", c.in, got.Raw, c.raw)
		}
	}
}

func TestClassifyTargetCIDRNotMistakenForDomain(t *testing.T) {
	// A CIDR must never be classified as a domain just because the heuristic
	// runs — order matters in ClassifyTarget.
	if got := ClassifyTarget("10.0.0.0/8"); got.Kind != KindCIDR {
		t.Errorf("expected CIDR, got %v", got.Kind)
	}
}

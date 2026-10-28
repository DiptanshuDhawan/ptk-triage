package nmap

import (
	"strings"
	"testing"

	"ptk/internal/model"
)

const sampleXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <hostnames><hostname name="dc01.target.local" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.2p2" method="probed"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" method="probed"/>
        <script id="smb-security-mode" output="message_signing: disabled"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="8443">
        <state state="open"/>
        <service name="https" method="table"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.10.10.6" addrtype="ipv4"/>
  </host>
</nmaprun>`

func TestParseBasic(t *testing.T) {
	res := Parse(strings.NewReader(sampleXML))
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", res.Warnings)
	}
	// 3 open ports (22, 445, 8443); closed 23 and down host excluded.
	if len(res.Items) != 3 {
		t.Fatalf("expected 3 open-port items, got %d: %+v", len(res.Items), res.Items)
	}

	byPort := map[int]int{}
	for i, it := range res.Items {
		byPort[it.Port] = i
		if it.Address != "10.10.10.5" {
			t.Errorf("port %d: wrong address %q", it.Port, it.Address)
		}
		if it.Host != "dc01.target.local" {
			t.Errorf("port %d: wrong hostname %q", it.Port, it.Host)
		}
	}

	ssh := res.Items[byPort[22]]
	if ssh.Service != "ssh" || !strings.Contains(ssh.Banner, "OpenSSH 7.2p2") {
		t.Errorf("ssh banner wrong: %+v", ssh)
	}

	smb := res.Items[byPort[445]]
	if !strings.Contains(smb.Scripts, "message_signing: disabled") {
		t.Errorf("smb script output not captured: %q", smb.Scripts)
	}

	https := res.Items[byPort[8443]]
	if https.Extra["service_guessed"] != "true" {
		t.Errorf("expected 8443 to be marked service_guessed (method=table), got %+v", https.Extra)
	}
}

func TestParseClosedAndDownExcluded(t *testing.T) {
	res := Parse(strings.NewReader(sampleXML))
	for _, it := range res.Items {
		if it.Port == 23 {
			t.Error("closed port 23 must not be surfaced")
		}
		if it.Address == "10.10.10.6" {
			t.Error("down host must not be surfaced")
		}
	}
}

func TestTruncatedHostSalvagesPorts(t *testing.T) {
	// Cut the XML partway through the <ports> block, after ports 22 and 445 are
	// fully written but before the host/ports close. A naive parser loses the
	// whole host; we must recover the complete ports.
	idx := strings.Index(sampleXML, `<port protocol="tcp" portid="23"`)
	if idx < 0 {
		t.Fatal("fixture layout changed")
	}
	truncated := sampleXML[:idx]

	res := Parse(strings.NewReader(truncated))
	if len(res.Warnings) == 0 {
		t.Error("expected a truncation warning")
	}
	foundPorts := map[int]bool{}
	for _, it := range res.Items {
		foundPorts[it.Port] = true
		if it.Address != "10.10.10.5" {
			t.Errorf("salvaged port %d lost host IP: %q", it.Port, it.Address)
		}
	}
	if !foundPorts[22] || !foundPorts[445] {
		t.Errorf("truncation salvage lost ports; got %v", foundPorts)
	}
}

func TestHostScriptAndOSCaptured(t *testing.T) {
	// Regression: host-level <hostscript> and <os> were previously dropped,
	// losing real recon signal (domain/OS). They must be attached to a port.
	const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery" output="OS: Windows Server 2019; Domain name: htb.local; FQDN: dc.htb.local"/>
    </hostscript>
    <os><osmatch name="Microsoft Windows Server 2019" accuracy="95"/></os>
  </host>
</nmaprun>`
	res := Parse(strings.NewReader(xml))

	var smb *model.Item
	for i := range res.Items {
		if res.Items[i].Port == 445 {
			smb = &res.Items[i]
		}
	}
	if smb == nil {
		t.Fatal("445 not parsed")
	}
	if !strings.Contains(smb.Scripts, "smb-os-discovery") {
		t.Errorf("host script not attached to SMB port: %q", smb.Scripts)
	}
	if !strings.Contains(smb.Scripts, "Windows Server 2019") {
		t.Errorf("os-match not attached: %q", smb.Scripts)
	}
	if smb.Extra["os"] == "" {
		t.Error("os not recorded in Extra")
	}
	// It must attach to exactly ONE port (445), not both.
	for _, it := range res.Items {
		if it.Port == 80 && strings.Contains(it.Scripts, "smb-os-discovery") {
			t.Error("host script wrongly duplicated onto port 80")
		}
	}
}

func TestUDPAndOpenFilteredPorts(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
      <port protocol="udp" portid="123"><state state="open|filtered"/><service name="ntp"/></port>
    </ports>
  </host>
</nmaprun>`
	res := Parse(strings.NewReader(xml))
	if len(res.Items) != 2 {
		t.Fatalf("expected 2 UDP items (open + open|filtered), got %d", len(res.Items))
	}
	for _, it := range res.Items {
		if it.Protocol != "udp" {
			t.Errorf("expected udp protocol, got %q", it.Protocol)
		}
	}
}

func TestMACAddressNotUsedAsHostIP(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <address addr="00:50:56:B9:3A:1F" addrtype="mac" vendor="VMware"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
  </host>
</nmaprun>`
	res := Parse(strings.NewReader(xml))
	if len(res.Items) != 1 || res.Items[0].Address != "10.0.0.5" {
		t.Fatalf("MAC address leaked as host IP: %+v", res.Items)
	}
}

func TestNotNmapXML(t *testing.T) {
	res := Parse(strings.NewReader(`{"not":"nmap"}`))
	if len(res.Items) != 0 {
		t.Error("should produce no items for non-nmap input")
	}
	if len(res.Warnings) == 0 {
		t.Error("should warn when no host elements found")
	}
}

func TestEmptyInput(t *testing.T) {
	res := Parse(strings.NewReader(""))
	if len(res.Items) != 0 {
		t.Error("empty input should yield no items")
	}
}

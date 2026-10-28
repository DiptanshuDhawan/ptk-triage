//go:build ignore

// stub is a fake recon tool used only for end-to-end testing of `ptk triage
// scan` without the real binaries. Built three times (as subfinder/nmap/ffuf),
// it inspects its own name and writes canned output to the file named by the
// relevant output flag, so the orchestrator's real stages run against real
// (tiny) artifacts.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func argAfter(flag string) string {
	for i, a := range os.Args {
		if a == flag && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

func main() {
	name := strings.ToLower(filepath.Base(os.Args[0]))
	name = strings.TrimSuffix(name, ".exe")

	switch {
	case strings.Contains(name, "subfinder"):
		if p := argAfter("-o"); p != "" {
			os.WriteFile(p, []byte("www.example.com\ndev.example.com\n"), 0o644)
		}
	case strings.Contains(name, "nmap"):
		if p := argAfter("-oX"); p != "" {
			os.WriteFile(p, []byte(nmapXML), 0o644)
		}
	case strings.Contains(name, "ffuf"):
		if p := argAfter("-o"); p != "" {
			os.WriteFile(p, []byte(ffufJSON), 0o644)
		}
	}
	fmt.Printf("[stub %s] args: %s\n", name, strings.Join(os.Args[1:], " "))
}

const nmapXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.2p2"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Apache Tomcat"/></port>
    </ports>
  </host>
</nmaprun>`

const ffufJSON = `{"results":[
{"input":{"FUZZ":".git/config"},"status":200,"length":92,"url":"http://127.0.0.1:8080/.git/config"},
{"input":{"FUZZ":"admin"},"status":403,"length":289,"url":"http://127.0.0.1:8080/admin"}
]}`

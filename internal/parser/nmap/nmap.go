// Package nmap parses nmap XML (-oX) output into normalized model.Items.
//
// We deliberately parse XML rather than the -oN grepable/normal text output:
// the XML schema is stable and unambiguous, whereas text output varies with
// nmap version and flags and is painful to parse reliably. A recon tool that
// silently drops a port because of a text-format quirk is dangerous, so we lean
// on the structured format.
//
// Robustness: interrupted scans produce truncated XML (no closing </nmaprun>).
// We handle that by decoding host elements incrementally with a streaming
// token decoder, so every fully-written <host> is captured even if the final
// one is cut off mid-write.
package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"ptk/internal/model"
)

// XML schema subset. We only declare the fields we consume.
type host struct {
	Status     status    `xml:"status"`
	Addresses  []address `xml:"address"`
	Hostnames  hostnames `xml:"hostnames"`
	Ports      ports     `xml:"ports"`
	HostScript []script  `xml:"hostscript>script"`
	OS         osInfo    `xml:"os"`
}

type osInfo struct {
	Matches []struct {
		Name     string `xml:"name,attr"`
		Accuracy string `xml:"accuracy,attr"`
	} `xml:"osmatch"`
}

type status struct {
	State string `xml:"state,attr"`
}

type address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"` // ipv4 / ipv6 / mac
}

type hostnames struct {
	Hostname []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostname"`
}

type ports struct {
	Port []port `xml:"port"`
}

type port struct {
	Protocol string   `xml:"protocol,attr"`
	PortID   int      `xml:"portid,attr"`
	State    pstate   `xml:"state"`
	Service  service  `xml:"service"`
	Scripts  []script `xml:"script"`
}

type pstate struct {
	State string `xml:"state,attr"`
}

type service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"` // "ssl" => likely https
	Method    string `xml:"method,attr"` // "table" means guessed, not probed
}

type script struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// ParseFile reads and parses an nmap XML file.
func ParseFile(path string) (model.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.ParseResult{Source: path}, err
	}
	defer f.Close()
	res := Parse(f)
	res.Source = path
	return res, nil
}

// Parse consumes an nmap XML stream. It never returns a hard error for
// malformed trailing data; instead it records a warning and returns every host
// — and, on a truncated host, every complete port — it managed to decode
// before the corruption.
//
// We read the whole stream into memory first (nmap XML is small) so that when a
// <host> is cut off mid-element we can re-scan its bytes and salvage the ports
// that were fully written. An interrupted scan with one host and many ports
// would otherwise lose everything, which for a recon tool is unacceptable.
func Parse(r io.Reader) model.ParseResult {
	var res model.ParseResult
	data, err := io.ReadAll(r)
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("read error: %v", err))
		return res
	}

	dec := xml.NewDecoder(bytes.NewReader(data))
	hostsSeen, salvagedHosts := 0, 0

	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			// Decoder position is unreliable after an error; salvage any
			// remaining whole <host> blocks from the raw bytes, then stop.
			n := salvageHosts(data, &res)
			salvagedHosts += n
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("input truncated/interrupted (%v); salvaged %d additional host block(s) from raw bytes", terr, n))
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "host" {
			continue
		}
		var h host
		if derr := dec.DecodeElement(&h, &se); derr != nil {
			// This host was likely cut off mid-element. Recover its complete
			// ports from the raw bytes rather than dropping the whole host.
			ports, pErr := salvagePortsAfter(data, se)
			res.Items = append(res.Items, ports...)
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("a <host> element was truncated (%v); salvaged %d complete port(s) from it", derr, len(ports)))
			if pErr != "" {
				res.Warnings = append(res.Warnings, pErr)
			}
			break
		}
		hostsSeen++
		res.Items = append(res.Items, hostToItems(h)...)
	}

	if hostsSeen == 0 && salvagedHosts == 0 && len(res.Items) == 0 && len(res.Warnings) == 0 {
		res.Warnings = append(res.Warnings, "no <host> elements found — is this nmap XML (-oX) output?")
	}
	return res
}

// salvageHosts scans raw bytes for complete <host>...</host> blocks and decodes
// each independently. Used when the main decoder errors between hosts.
func salvageHosts(data []byte, res *model.ParseResult) int {
	n := 0
	rest := data
	for {
		start := bytes.Index(rest, []byte("<host"))
		if start < 0 {
			break
		}
		end := bytes.Index(rest[start:], []byte("</host>"))
		if end < 0 {
			break // trailing host is incomplete; handled elsewhere
		}
		block := rest[start : start+end+len("</host>")]
		var h host
		if err := xml.Unmarshal(block, &h); err == nil {
			res.Items = append(res.Items, hostToItems(h)...)
			n++
		}
		rest = rest[start+end+len("</host>"):]
	}
	return n
}

// salvagePortsAfter recovers complete <port>...</port> elements belonging to a
// host whose closing tag never arrived. It reconstructs host identity (address,
// hostname) from the opening attributes/leading bytes when available.
func salvagePortsAfter(data []byte, se xml.StartElement) ([]model.Item, string) {
	// Find where this host element began in the raw bytes. We match "<host"
	// only when followed by a space or newline so we don't land on the nested
	// "<hostnames>"/"<hostname>" tags. We take the last such host — the
	// truncated one.
	hostStart := lastHostStart(data)
	if hostStart < 0 {
		return nil, ""
	}
	region := data[hostStart:]

	// Pull host-level identity from the partial region.
	ip := firstAttr(region, "addr=")
	hostname := firstTag(region, "<hostname", "name=")

	var items []model.Item
	rest := region
	for {
		ps := bytes.Index(rest, []byte("<port "))
		if ps < 0 {
			ps = bytes.Index(rest, []byte("<port>"))
		}
		if ps < 0 {
			break
		}
		pe := bytes.Index(rest[ps:], []byte("</port>"))
		if pe < 0 {
			break // this port is the truncated one
		}
		block := rest[ps : ps+pe+len("</port>")]
		var p port
		if err := xml.Unmarshal(block, &p); err == nil {
			if it, ok := portToItem(p, ip, hostname); ok {
				items = append(items, it)
			}
		}
		rest = rest[ps+pe+len("</port>"):]
	}
	return items, ""
}

// lastHostStart returns the byte offset of the last real "<host" element start
// (followed by whitespace), ignoring nested "<hostnames>"/"<hostname>".
func lastHostStart(data []byte) int {
	best := -1
	from := 0
	for {
		i := bytes.Index(data[from:], []byte("<host"))
		if i < 0 {
			break
		}
		abs := from + i
		after := abs + len("<host")
		if after < len(data) {
			c := data[after]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '>' {
				best = abs
			}
		}
		from = abs + len("<host")
	}
	return best
}

// firstAttr extracts the first value of an attribute like addr="..." from raw
// bytes (best-effort, used only in the salvage path).
func firstAttr(b []byte, attr string) string {
	i := bytes.Index(b, []byte(attr+`"`))
	if i < 0 {
		return ""
	}
	i += len(attr) + 1
	j := bytes.IndexByte(b[i:], '"')
	if j < 0 {
		return ""
	}
	return string(b[i : i+j])
}

// firstTag finds the first occurrence of a tag and extracts one of its attrs.
func firstTag(b []byte, tag, attr string) string {
	i := bytes.Index(b, []byte(tag))
	if i < 0 {
		return ""
	}
	return firstAttr(b[i:], attr)
}

func hostToItems(h host) []model.Item {
	// A down host contributes nothing actionable.
	if strings.EqualFold(h.Status.State, "down") {
		return nil
	}

	ip := primaryIP(h.Addresses)
	hostname := ""
	if len(h.Hostnames.Hostname) > 0 {
		hostname = h.Hostnames.Hostname[0].Name
	}

	var items []model.Item
	for _, p := range h.Ports.Port {
		if it, ok := portToItem(p, ip, hostname); ok {
			items = append(items, it)
		}
	}

	// Host-level scripts (<hostscript>) and OS detection describe the whole
	// host, not a single port. Dropping them loses real recon signal (e.g.
	// smb-os-discovery revealing the domain and Windows build). Attach the
	// combined host-script text + OS match to one representative item — prefer
	// SMB (445/139), then RPC (135), then the first open port — so rules can
	// match it exactly once rather than N times across every port.
	hs := buildScripts(h.HostScript)
	osNote := ""
	if len(h.OS.Matches) > 0 {
		osNote = "os-match: " + h.OS.Matches[0].Name + " (accuracy " + h.OS.Matches[0].Accuracy + ")"
	}
	if (hs != "" || osNote != "") && len(items) > 0 {
		idx := representativePort(items)
		combined := strings.TrimSpace(items[idx].Scripts + "\n" + hs + "\n" + osNote)
		items[idx].Scripts = combined
		if osNote != "" {
			items[idx].Extra["os"] = h.OS.Matches[0].Name
		}
	}
	return items
}

// representativePort picks the index of the item host-wide scripts should
// attach to: SMB first (that is where OS-discovery info is most relevant),
// then RPC, else the first.
func representativePort(items []model.Item) int {
	for _, want := range []int{445, 139, 135} {
		for i, it := range items {
			if it.Port == want {
				return i
			}
		}
	}
	return 0
}

// portToItem converts one parsed <port> into a normalized Item given the host's
// IP and hostname. Returns ok=false for ports that are not open. Shared by the
// normal path and the truncation-salvage path.
func portToItem(p port, ip, hostname string) (model.Item, bool) {
	st := strings.ToLower(p.State.State)
	if st != "open" && st != "open|filtered" {
		return model.Item{}, false
	}

	it := model.Item{
		Kind:     model.KindHost,
		Address:  ip,
		Host:     hostname,
		Port:     p.PortID,
		Protocol: p.Protocol,
		State:    p.State.State,
		Service:  p.Service.Name,
		Product:  p.Service.Product,
		Version:  p.Service.Version,
		Extra:    map[string]string{},
	}
	it.Banner = buildBanner(p.Service)
	it.Scripts = buildScripts(p.Scripts)

	if p.Service.Tunnel == "ssl" {
		it.Extra["tls"] = "true"
	}
	if p.Service.Method == "table" {
		// nmap guessed this from the port number, it did not probe it.
		it.Extra["service_guessed"] = "true"
	}
	if len(p.Scripts) > 0 {
		ids := make([]string, 0, len(p.Scripts))
		for _, s := range p.Scripts {
			ids = append(ids, s.ID)
		}
		it.Extra["scripts"] = strings.Join(ids, ",")
	}
	return it, true
}

// primaryIP prefers IPv4, then IPv6, then any non-MAC address.
func primaryIP(addrs []address) string {
	for _, a := range addrs {
		if a.AddrType == "ipv4" {
			return a.Addr
		}
	}
	for _, a := range addrs {
		if a.AddrType == "ipv6" {
			return a.Addr
		}
	}
	for _, a := range addrs {
		if a.AddrType != "mac" {
			return a.Addr
		}
	}
	return ""
}

// buildBanner joins product, version and extrainfo into the string rules match
// against, e.g. "OpenSSH 7.2p2 Ubuntu 4ubuntu2.8".
func buildBanner(s service) string {
	parts := make([]string, 0, 3)
	for _, v := range []string{s.Product, s.Version, s.ExtraInfo} {
		if strings.TrimSpace(v) != "" {
			parts = append(parts, strings.TrimSpace(v))
		}
	}
	return strings.Join(parts, " ")
}

// buildScripts flattens NSE script output into one searchable block prefixed by
// each script id, so rules can match either the id (e.g. "smb-os-discovery") or
// the output text (e.g. "anonymous").
func buildScripts(scripts []script) string {
	if len(scripts) == 0 {
		return ""
	}
	var b strings.Builder
	for _, s := range scripts {
		b.WriteString(s.ID)
		b.WriteString(": ")
		b.WriteString(strings.ReplaceAll(s.Output, "\n", " "))
		b.WriteString("\n")
	}
	return b.String()
}

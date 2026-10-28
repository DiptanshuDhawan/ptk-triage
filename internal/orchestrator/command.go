package orchestrator

import (
	"fmt"
	"net/url"
	"strings"

	"ptk/internal/model"
)

// This file holds the pure command-construction logic: given a target, output
// path and options, produce the exact argv to run. Keeping these as plain
// functions (no exec, no I/O) makes the part most likely to harbor a
// silent-but-dangerous bug — wrong flags producing wrong or no output — trivial
// to unit test and to preview via --dry-run.

// DefaultNmapArgs is the scan ptk runs when the user doesn't override it.
// Rationale:
//   - -sT (TCP connect) works WITHOUT root/Administrator on every OS, so the
//     default never silently fails for lack of privileges. Users who are
//     elevated and want a SYN scan pass --nmap-args "-sS ...".
//   - -sV gives service/version banners, which the version/aged-banner rules
//     depend on.
//   - -sC runs nmap's default NSE scripts, which the engine's script-output
//     rules (smb-os-discovery, anonymous access, vuln flags, ...) read — so the
//     default scan directly feeds the default ruleset.
//   - --top-ports 1000 keeps the default fast; use --nmap-args "-p-" for all.
func DefaultNmapArgs() []string {
	return []string{"-sT", "-sV", "-sC", "--top-ports", "1000"}
}

// SubfinderArgs: subfinder -d <domain> -silent -o <outFile>
func SubfinderArgs(domain, outFile string) []string {
	return []string{"-d", domain, "-silent", "-o", outFile}
}

// AmassArgs: amass enum -passive -d <domain> -o <outFile>
// Passive mode only — ptk never runs amass's active/brute modes implicitly.
func AmassArgs(domain, outFile string) []string {
	return []string{"enum", "-passive", "-d", domain, "-o", outFile}
}

// AssetfinderArgs: assetfinder --subs-only <domain>
// assetfinder writes to stdout, so the caller captures it rather than passing
// an output path.
func AssetfinderArgs(domain string) []string {
	return []string{"--subs-only", domain}
}

// NmapArgs assembles the full nmap argv (excluding the binary): the chosen
// scan args, then -oX <outFile>, then the targets. extraArgs, when non-empty,
// fully replaces DefaultNmapArgs so the user has complete control; we always
// append -oX and the targets ourselves since those are not optional.
func NmapArgs(extraArgs []string, outFile string, targets []string) []string {
	base := extraArgs
	if len(base) == 0 {
		base = DefaultNmapArgs()
	}
	args := make([]string, 0, len(base)+2+len(targets))
	args = append(args, base...)
	args = append(args, "-oX", outFile)
	args = append(args, targets...)
	return args
}

// FfufArgs assembles the ffuf argv. extraArgs is inserted before the output
// flags so a user passthrough can add matchers/filters/headers without us
// losing control of -o/-of (which the parser depends on). -s runs ffuf in
// quiet mode; the JSON file is the real output.
func FfufArgs(wordlist, fuzzURL, outFile string, extraArgs []string) []string {
	args := []string{"-w", wordlist, "-u", fuzzURL}
	args = append(args, extraArgs...)
	args = append(args, "-o", outFile, "-of", "json", "-s")
	return args
}

// WebTarget is a discovered HTTP(S) endpoint worth fuzzing.
type WebTarget struct {
	URL  string // e.g. https://10.0.0.5:8443
	Host string // host or IP used in the URL
	Port int
}

// FuzzURL appends the ffuf FUZZ keyword to the web target's base URL.
func (wt WebTarget) FuzzURL() string {
	return strings.TrimRight(wt.URL, "/") + "/FUZZ"
}

// FfufOutName is the per-target output file name: ffuf_<host>_<port>.json with
// the host sanitized so it's filesystem-safe.
func (wt WebTarget) FfufOutName() string {
	host := sanitizeForFilename(wt.Host)
	return fmt.Sprintf("ffuf_%s_%d.json", host, wt.Port)
}

// WebTargets extracts the HTTP(S) services worth fuzzing from parsed nmap host
// items, de-duplicated by URL. It mirrors the engine's own notion of "is this
// actually a browseable web port" so ptk doesn't fuzz RPC-over-HTTP (593) or
// the Windows HTTPAPI/WinRM stack (5985/47001).
func WebTargets(items []model.Item) []WebTarget {
	seen := map[string]bool{}
	var out []WebTarget
	for _, it := range items {
		if it.Kind != model.KindHost {
			continue
		}
		if !isWebService(it) {
			continue
		}
		host := it.Host
		if host == "" {
			host = it.Address
		}
		if host == "" {
			continue
		}
		scheme := "http"
		if isTLS(it) {
			scheme = "https"
		}
		u := fmt.Sprintf("%s://%s:%d", scheme, host, it.Port)
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, WebTarget{URL: u, Host: host, Port: it.Port})
	}
	return out
}

// isWebService decides whether an nmap host item is a browseable web service.
// Excludes services that merely contain "http" in their name/product but are
// not websites: RPC-over-HTTP (ncacn_http), and the Windows HTTPAPI stack that
// backs WinRM/WSMan.
func isWebService(it model.Item) bool {
	svc := strings.ToLower(it.Service)
	prod := strings.ToLower(it.Product)
	if strings.Contains(svc, "ncacn") || strings.Contains(svc, "rpc") || strings.Contains(svc, "soap") {
		return false
	}
	if strings.Contains(prod, "rpc") || strings.Contains(prod, "httpapi") {
		return false
	}
	switch svc {
	case "http", "https", "http-alt", "http-proxy", "https-alt", "http-mgmt", "ssl/http":
		return true
	}
	if strings.Contains(prod, "http") {
		return true
	}
	// Fall back to well-known web ports even when the service name is vague
	// (e.g. tcpwrapped on 8080), since those are worth a fuzzing attempt.
	switch it.Port {
	case 80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 3000, 5000:
		return true
	}
	return false
}

// isTLS reports whether the web service should be addressed over https.
func isTLS(it model.Item) bool {
	svc := strings.ToLower(it.Service)
	if strings.Contains(svc, "https") || strings.Contains(svc, "ssl") {
		return true
	}
	if it.Extra != nil && it.Extra["tls"] == "true" {
		return true
	}
	switch it.Port {
	case 443, 8443:
		return true
	}
	return false
}

// ProbeURLs returns the candidate base URLs to try when fuzzing a target
// directly (no nmap results to go on), newest-first by likelihood.
func ProbeURLs(host string) []string {
	return []string{"https://" + host, "http://" + host}
}

func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "host"
	}
	return out
}

// validateURL is a defensive guard used before building a fuzz URL from
// untrusted discovered data.
func validateURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

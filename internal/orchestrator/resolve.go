package orchestrator

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolution of discovered subdomains is done natively in Go rather than by
// shelling out to another tool: it needs no external binary, and it yields
// exactly the signals the subdomain rules want — an A record (for feeding nmap
// and for off-range/no-web checks) and, crucially, the CNAME-with-no-A case
// that the dangling-CNAME takeover rule keys on. HTTP probing is likewise
// native and optional.
//
// Both the resolver and the prober are interfaces so the enrichment logic is
// testable deterministically, without DNS or network access.

// Resolver looks up a hostname's A/AAAA records and its CNAME target.
type Resolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
	LookupCNAME(ctx context.Context, host string) (cname string, err error)
}

// Prober checks whether an HTTP(S) service answers for a host, returning the
// status code of the first scheme that responds.
type Prober interface {
	Probe(ctx context.Context, host string) (status int, scheme string, up bool)
}

// ResolvedSub is the enriched result for one subdomain.
type ResolvedSub struct {
	Name     string
	Addrs    []string
	CNAME    string
	Resolved bool
	Status   int
	Scheme   string // http/https when the probe answered
	HTTPUp   bool
}

// CSVLine renders the result as a line the subs parser understands:
// "name,ip,status,cname" with fields omitted when unknown. The CNAME is kept
// for both resolved and unresolved hosts: resolved third-party CNAMEs are useful
// low-severity watch-items, while CNAME+no-IP is the HIGH dangling/takeover
// signal. The subs parser is order-independent and tolerant of empty fields,
// so this round-trips cleanly through `triage subs` / `triage all`.
func (r ResolvedSub) CSVLine() string {
	ip := ""
	if len(r.Addrs) > 0 {
		ip = r.Addrs[0]
	}
	status := ""
	if r.Status > 0 {
		status = fmt.Sprintf("%d", r.Status)
	}
	return strings.Join([]string{r.Name, ip, status, r.CNAME}, ",")
}

// Enrich resolves and (optionally) probes a list of subdomain names
// concurrently, returning results sorted by name for deterministic output.
// concurrency caps in-flight lookups; <=0 uses a sensible default.
func Enrich(ctx context.Context, names []string, res Resolver, probe Prober, concurrency int) []ResolvedSub {
	if concurrency <= 0 {
		concurrency = 20
	}
	names = dedupeStrings(names)

	results := make([]ResolvedSub, len(names))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, name := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = enrichOne(ctx, name, res, probe)
		}(i, name)
	}
	wg.Wait()

	sort.Slice(results, func(a, b int) bool { return results[a].Name < results[b].Name })
	return results
}

func enrichOne(ctx context.Context, name string, res Resolver, probe Prober) ResolvedSub {
	out := ResolvedSub{Name: name}
	if res != nil {
		if addrs, err := res.LookupHost(ctx, name); err == nil && len(addrs) > 0 {
			out.Addrs = addrs
			out.Resolved = true
		}
		if cname, err := res.LookupCNAME(ctx, name); err == nil {
			cname = strings.TrimSuffix(cname, ".")
			if !strings.EqualFold(cname, name) {
				out.CNAME = cname
			}
		}
	}
	if probe != nil && out.Resolved {
		if status, scheme, up := probe.Probe(ctx, name); up {
			out.Status = status
			out.Scheme = scheme
			out.HTTPUp = true
		}
	}
	return out
}

// UniqueIPs collects the distinct resolved A-record addresses across results,
// sorted — this is the host list fed to nmap for a domain target.
func UniqueIPs(subs []ResolvedSub) []string {
	set := map[string]bool{}
	for _, s := range subs {
		for _, a := range s.Addrs {
			if a != "" {
				set[a] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func dedupeStrings(in []string) []string {
	set := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || set[s] {
			continue
		}
		set[s] = true
		out = append(out, s)
	}
	return out
}

// --- real implementations --------------------------------------------------

// netResolver is the production Resolver backed by the Go stdlib resolver.
type netResolver struct{ r *net.Resolver }

// NewResolver returns a Resolver using the system DNS configuration.
func NewResolver() Resolver { return netResolver{r: net.DefaultResolver} }

func (n netResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.r.LookupHost(ctx, host)
}

func (n netResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return n.r.LookupCNAME(ctx, host)
}

// httpProber is the production Prober. It issues a short-timeout HEAD-like GET
// to https then http, following redirects, and does not verify TLS certs
// (self-signed is expected on engagement hosts).
type httpProber struct {
	client *http.Client
}

// NewProber returns a Prober with the given per-request timeout. Certificate
// verification is intentionally disabled: self-signed certificates are normal
// on internal engagement infrastructure, and this probe asks only "did an HTTPS
// server answer?" — it does not establish trust or send credentials.
func NewProber(timeout time.Duration) Prober {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // deliberate recon probe; see comment above
	return httpProber{client: &http.Client{Timeout: timeout, Transport: transport}}
}

func (h httpProber) Probe(ctx context.Context, host string) (int, string, bool) {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := h.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		return resp.StatusCode, scheme, true
	}
	return 0, "", false
}

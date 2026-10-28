package orchestrator

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ptk/internal/parser/nmap"
)

// Options controls a scan run.
type Options struct {
	OutDir      string        // engagement folder; created if absent
	Wordlist    string        // explicit ffuf wordlist; "" => auto-detect
	NmapArgs    []string      // override DefaultNmapArgs entirely when non-empty
	FfufArgs    []string      // extra ffuf flags (matchers/filters/headers)
	SkipSubs    bool          // skip subdomain enumeration
	SkipNmap    bool          // skip port scanning
	SkipFfuf    bool          // skip web fuzzing
	Probe       bool          // HTTP-probe resolved subdomains
	MaxFfuf     int           // cap concurrent/total ffuf runs (0 => default 10)
	ToolTimeout time.Duration // per-tool timeout (0 => none)
	DryRun      bool          // print the plan, execute nothing, touch nothing
}

// Flow holds the injected collaborators that make the orchestration testable:
// tool availability, the process runner, the DNS resolver and HTTP prober, and
// the sink for live progress output.
type Flow struct {
	Tools    map[string]ToolStatus
	Runner   Runner
	Resolver Resolver
	Prober   Prober
	Log      io.Writer // live tool output + progress; nil => os.Stderr
}

// Result reports what a run produced.
type Result struct {
	OutDir    string
	Warnings  []string
	Artifacts []string // files written that the triage step will read
	Ran       []string // human descriptions of the stages actually executed
}

const (
	fileSubsCSV = "subs_resolved.csv"
	fileNmapXML = "nmap.xml"
	dirRaw      = "raw"
	fileRunLog  = "run.log"
)

// NewFlow builds a production Flow with real collaborators and the given tool
// statuses and progress sink.
func NewFlow(tools map[string]ToolStatus, log io.Writer) *Flow {
	if log == nil {
		log = os.Stderr
	}
	return &Flow{
		Tools:    tools,
		Runner:   ExecRunner{},
		Resolver: NewResolver(),
		Prober:   NewProber(5 * time.Second),
		Log:      log,
	}
}

func (f *Flow) logf(format string, a ...any) {
	fmt.Fprintf(f.Log, format+"\n", a...)
}

func (f *Flow) available(key string) (ToolStatus, bool) {
	st, ok := f.Tools[key]
	return st, ok && st.Found
}

// Run executes the full orchestration for a target, writing artifacts into
// opts.OutDir and returning what it produced. It never returns an error for a
// missing tool or a tool that exits nonzero — those become warnings and the
// run continues, so you always get a report over whatever was gathered.
func (f *Flow) Run(ctx context.Context, t Target, opts Options) (Result, error) {
	res := Result{OutDir: opts.OutDir}

	if err := os.MkdirAll(filepath.Join(opts.OutDir, dirRaw), 0o755); err != nil {
		return res, fmt.Errorf("creating output folder: %w", err)
	}

	runlog, err := os.Create(filepath.Join(opts.OutDir, dirRaw, fileRunLog))
	if err != nil {
		return res, fmt.Errorf("creating run log: %w", err)
	}
	defer runlog.Close()
	// Everything printed via logf also lands in run.log for provenance.
	userLog := f.Log
	f.Log = io.MultiWriter(userLog, runlog)
	defer func() { f.Log = userLog }()

	f.logf("[*] target %s (%s)  ->  %s", t.Raw, t.Kind, opts.OutDir)

	var subNames []string
	if t.Kind == KindDomain && !opts.SkipSubs {
		subNames = f.stageSubs(ctx, t.Raw, opts, &res)
	} else if t.Kind != KindDomain && !opts.SkipSubs {
		res.Warnings = append(res.Warnings, fmt.Sprintf("subdomain enumeration skipped — target is a %s, not a domain", t.Kind))
	}

	scanHosts := f.stageResolve(ctx, t, subNames, opts, &res)

	if !opts.SkipNmap {
		f.stageNmap(ctx, scanHosts, opts, &res)
	} else {
		res.Warnings = append(res.Warnings, "nmap stage skipped (--skip-nmap)")
	}

	if !opts.SkipFfuf {
		f.stageFfuf(ctx, t, opts, &res)
	} else {
		res.Warnings = append(res.Warnings, "ffuf stage skipped (--skip-ffuf)")
	}

	return res, nil
}

// stageSubs runs subfinder (required) plus amass/assetfinder (optional) and
// returns the merged, de-duplicated subdomain names.
func (f *Flow) stageSubs(ctx context.Context, domain string, opts Options, res *Result) []string {
	st, ok := f.available("subfinder")
	names := map[string]bool{}

	if ok {
		out := filepath.Join(opts.OutDir, dirRaw, "subfinder.txt")
		f.logf("[*] subfinder: enumerating %s", domain)
		if err := f.run(ctx, st.Path, SubfinderArgs(domain, out), opts); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("subfinder exited with error (keeping any partial output): %v", err))
		}
		for _, n := range readLines(out) {
			names[strings.ToLower(n)] = true
		}
		res.Ran = append(res.Ran, "subfinder")
	} else {
		res.Warnings = append(res.Warnings, "subfinder not found — subdomain enumeration is passive-only without it; install it or supply a subs file to `triage subs`")
	}

	if st, ok := f.available("amass"); ok {
		out := filepath.Join(opts.OutDir, dirRaw, "amass.txt")
		f.logf("[*] amass: passive enumeration of %s", domain)
		if err := f.run(ctx, st.Path, AmassArgs(domain, out), opts); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("amass exited with error (optional, continuing): %v", err))
		}
		for _, n := range readLines(out) {
			names[strings.ToLower(n)] = true
		}
		res.Ran = append(res.Ran, "amass")
	}

	// Run assetfinder if available
	if st, ok := f.available("assetfinder"); ok {
		f.logf("[*] assetfinder: enumerating %s", domain)
		// assetfinder writes to stdout, so we need to capture its output
		assetfinderOut := filepath.Join(opts.OutDir, dirRaw, "assetfinder.txt")
		assetfinderFile, err := os.Create(assetfinderOut)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("could not create assetfinder output file: %v", err))
		} else {
			cmdRunner := CapturingRunner{Inner: f.Runner}
			if err := cmdRunner.RunCapture(ctx, st.Path, AssetfinderArgs(domain), f.Log, assetfinderFile); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("assetfinder exited with error (optional, continuing): %v", err))
			}
			assetfinderFile.Close()
			for _, n := range readLines(assetfinderOut) {
				names[strings.ToLower(n)] = true
			}
			res.Ran = append(res.Ran, "assetfinder")
		}
	}

	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	f.logf("[+] %d unique subdomain name(s) discovered", len(out))
	return out
}

// stageResolve resolves+probes discovered names (for a domain target) into
// subs_resolved.csv and returns the host list nmap should scan. For an IP/CIDR
// target it simply returns the target itself.
func (f *Flow) stageResolve(ctx context.Context, t Target, subNames []string, opts Options, res *Result) []string {
	if t.Kind != KindDomain {
		return []string{t.Raw}
	}

	names := append([]string{t.Raw}, subNames...)
	resolved := Enrich(ctx, names, f.Resolver, proberOrNil(f.Prober, opts.Probe), 20)

	var lines []string
	for _, r := range resolved {
		lines = append(lines, r.CSVLine())
	}
	csvPath := filepath.Join(opts.OutDir, fileSubsCSV)
	if err := writeLines(csvPath, append([]string{"# subdomain,ip,status,cname  (generated by ptk triage scan)"}, lines...)); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("could not write %s: %v", fileSubsCSV, err))
	} else {
		res.Artifacts = append(res.Artifacts, csvPath)
		res.Ran = append(res.Ran, "resolve")
	}

	hosts := UniqueIPs(resolved)
	f.logf("[+] %d subdomain(s) resolved to %d unique IP(s)", countResolved(resolved), len(hosts))
	if len(hosts) == 0 {
		res.Warnings = append(res.Warnings, "no subdomains resolved to an IP; scanning the apex domain directly")
		return []string{t.Raw}
	}
	return hosts
}

// stageNmap runs nmap against the host list into nmap.xml.
func (f *Flow) stageNmap(ctx context.Context, hosts []string, opts Options, res *Result) {
	st, ok := f.available("nmap")
	if !ok {
		res.Warnings = append(res.Warnings, "nmap not found — port/service scanning skipped; "+st.Tool.InstallHint())
		return
	}
	if len(hosts) == 0 {
		res.Warnings = append(res.Warnings, "nmap stage had no hosts to scan")
		return
	}
	out := filepath.Join(opts.OutDir, fileNmapXML)
	f.logf("[*] nmap: scanning %d host(s)", len(hosts))
	if err := f.run(ctx, st.Path, NmapArgs(opts.NmapArgs, out, hosts), opts); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("nmap exited with error (keeping any partial XML): %v", err))
	}
	if fileExists(out) {
		res.Artifacts = append(res.Artifacts, out)
		res.Ran = append(res.Ran, "nmap")
	}
}

// stageFfuf fuzzes each web service nmap discovered. If nmap produced nothing
// (skipped/failed) it falls back to probing the target's own 80/443.
func (f *Flow) stageFfuf(ctx context.Context, t Target, opts Options, res *Result) {
	st, ok := f.available("ffuf")
	if !ok {
		res.Warnings = append(res.Warnings, "ffuf not found — web fuzzing skipped; "+st.Tool.InstallHint())
		return
	}

	wordlist, found := FindWordlist(opts.Wordlist, fileExists)
	if !found {
		res.Warnings = append(res.Warnings, "no ffuf wordlist found — pass --wordlist <path>; web fuzzing skipped")
		return
	}

	var targets []WebTarget
	nmapOut := filepath.Join(opts.OutDir, fileNmapXML)
	if fileExists(nmapOut) {
		if pr, err := nmap.ParseFile(nmapOut); err == nil {
			targets = WebTargets(pr.Items)
		}
	}
	if len(targets) == 0 {
		// Fall back to the target itself if it answers on a web port.
		host := t.Raw
		if t.Kind == KindCIDR {
			res.Warnings = append(res.Warnings, "ffuf stage: no web services discovered and target is a CIDR; nothing to fuzz")
			return
		}
		if status, scheme, up := f.Prober.Probe(ctx, host); up {
			targets = []WebTarget{{URL: scheme + "://" + host, Host: host, Port: defaultPort(scheme)}}
			f.logf("[*] ffuf: no nmap web services; target answered on %s (HTTP %d)", scheme, status)
		}
	}
	if len(targets) == 0 {
		res.Warnings = append(res.Warnings, "ffuf stage: no HTTP/S services to fuzz")
		return
	}

	max := opts.MaxFfuf
	if max <= 0 {
		max = 10
	}
	if len(targets) > max {
		res.Warnings = append(res.Warnings, fmt.Sprintf("ffuf: %d web services found, fuzzing the first %d (raise with --max-ffuf)", len(targets), max))
		targets = targets[:max]
	}

	f.logf("[*] ffuf: fuzzing %d web service(s) with %s", len(targets), wordlist)
	for _, wt := range targets {
		if !validateURL(wt.URL) {
			continue
		}
		out := filepath.Join(opts.OutDir, wt.FfufOutName())
		f.logf("    -> %s", wt.FuzzURL())
		if err := f.run(ctx, st.Path, FfufArgs(wordlist, wt.FuzzURL(), out, opts.FfufArgs), opts); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("ffuf on %s exited with error (keeping any partial output): %v", wt.URL, err))
		}
		if fileExists(out) {
			res.Artifacts = append(res.Artifacts, out)
		}
	}
	res.Ran = append(res.Ran, "ffuf")
}

// run executes one tool command, applying a per-tool timeout if configured.
func (f *Flow) run(ctx context.Context, bin string, args []string, opts Options) error {
	if opts.ToolTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.ToolTimeout)
		defer cancel()
	}
	f.logf("    $ %s %s", filepath.Base(bin), strings.Join(args, " "))
	return f.Runner.Run(ctx, bin, args, f.Log)
}

// DryRun prints the exact plan — every command that would run, in order —
// without executing anything, touching the network, or creating files. For
// data-dependent stages it prints the command template with the information
// available up front.
func (f *Flow) DryRun(t Target, opts Options) {
	f.logf("DRY RUN — no commands are executed, no files are written")
	f.logf("target : %s (%s)", t.Raw, t.Kind)
	f.logf("output : %s/", opts.OutDir)
	f.logf("")

	step := 1
	emit := func(label, bin string, args []string) {
		f.logf("%d) %-10s $ %s %s", step, label, bin, strings.Join(args, " "))
		step++
	}

	if t.Kind == KindDomain && !opts.SkipSubs {
		if st, ok := f.available("subfinder"); ok {
			emit("subfinder", binName(st), SubfinderArgs(t.Raw, filepath.Join(opts.OutDir, dirRaw, "subfinder.txt")))
		} else {
			f.logf("   (subfinder not found — would be skipped with a warning)")
		}
		if st, ok := f.available("amass"); ok {
			emit("amass", binName(st), AmassArgs(t.Raw, filepath.Join(opts.OutDir, dirRaw, "amass.txt")))
		}
		if st, ok := f.available("assetfinder"); ok {
			emit("assetfinder", binName(st), AssetfinderArgs(t.Raw))
			f.logf("                (output captured to %s)", filepath.Join(opts.OutDir, dirRaw, "assetfinder.txt"))
		}
		f.logf("%d) resolve    native DNS + optional HTTP probe of discovered names -> %s", step, fileSubsCSV)
		step++
	}

	nmapTargets := []string{t.Raw}
	if t.Kind == KindDomain {
		nmapTargets = []string{"<resolved IPs from the resolve step, or " + t.Raw + " if none>"}
	}
	if !opts.SkipNmap {
		if st, ok := f.available("nmap"); ok {
			emit("nmap", binName(st), NmapArgs(opts.NmapArgs, filepath.Join(opts.OutDir, fileNmapXML), nmapTargets))
		} else {
			f.logf("   (nmap not found — would be skipped with a warning)")
		}
	}

	if !opts.SkipFfuf {
		wordlist, found := FindWordlist(opts.Wordlist, fileExists)
		if !found {
			wordlist = "<no wordlist found; pass --wordlist>"
		}
		if _, ok := f.available("ffuf"); ok {
			f.logf("%d) ffuf       for each HTTP/S service nmap discovers:", step)
			f.logf("              $ ffuf %s", strings.Join(FfufArgs(wordlist, "<scheme>://<host>:<port>/FUZZ", filepath.Join(opts.OutDir, "ffuf_<host>_<port>.json"), opts.FfufArgs), " "))
			step++
		} else {
			f.logf("   (ffuf not found — would be skipped with a warning)")
		}
	}

	f.logf("")
	f.logf("%d) triage     parse every artifact in %s/ and print the ranked report", step, opts.OutDir)
}

// --- small helpers ---------------------------------------------------------

func proberOrNil(p Prober, enabled bool) Prober {
	if !enabled {
		return nil
	}
	return p
}

func binName(st ToolStatus) string {
	if st.Path != "" {
		return filepath.Base(st.Path)
	}
	if len(st.Tool.Bins) > 0 {
		return st.Tool.Bins[0]
	}
	return st.Tool.Key
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

func countResolved(subs []ResolvedSub) int {
	n := 0
	for _, s := range subs {
		if s.Resolved {
			n++
		}
	}
	return n
}

// DefaultWordlists are common SecLists/dirb locations checked when no explicit
// --wordlist is given.
func DefaultWordlists() []string {
	return []string{
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/dirb/wordlists/common.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
	}
}

// FindWordlist returns the explicit wordlist if it exists, else the first
// existing default location. exists is injected for testability.
func FindWordlist(explicit string, exists func(string) bool) (string, bool) {
	if explicit != "" {
		if exists(explicit) {
			return explicit, true
		}
		return "", false
	}
	for _, w := range DefaultWordlists() {
		if exists(w) {
			return w, true
		}
	}
	return "", false
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

func writeLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// DefaultOutDir builds a timestamped engagement folder name for a target when
// the user doesn't pass -o.
func DefaultOutDir(t Target) string {
	safe := sanitizeForFilename(t.Raw)
	return fmt.Sprintf("ptk-%s-%s", safe, time.Now().Format("20060102-150405"))
}

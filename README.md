# ptk triage

**Recon triage for pentesters — signal over noise.**

`ptk triage` parses raw output from `nmap`, `ffuf`, and subdomain enumeration
tools, applies a tunable rule engine, and prints a short, prioritized list of
findings that each answer *why this matters* — instead of making you re-read
hundreds of lines of raw scan output.

Built for HTB CPTS labs and real engagements: single static Go binary, fast,
and designed to be run after every scan.

```
ptk triage report
findings: HIGH 7  MED 5  LOW 6  INFO 0

[HIGH]   10.10.10.5:445    SMB exposed — enumerate shares, check null/anonymous session, signing, and known RCE (MS17-010 etc.)
[HIGH]   10.10.10.5:88     Kerberos present — Domain Controller likely; try AS-REP roasting and user enumeration
[HIGH]   dev.target.com    Dangling CNAME -> dev.s3.amazonaws.com — possible subdomain takeover
[MED]    10.10.10.5:5985   HTTP service on non-standard port 5985 — worth manual inspection
[LOW]    10.10.10.5:22     Older OpenSSH (OpenSSH 7.2) — enumerate users (pre-7.7 CVE-2018-15473) and check version CVEs
```

---

## Install

Requires Go 1.21+.

```bash
# from the project directory
go build -o ptk .

# or install into $GOBIN / $GOPATH/bin
go install .
```

On Windows PowerShell the binary is `ptk.exe`. All examples below use `ptk`.

The default ruleset is **embedded in the binary**, so it works with zero config.

---

## Usage

The CLI is structured like `git`/`docker` — a root with subcommands:

```
ptk triage nmap <file.xml>      Triage nmap XML (-oX) output
ptk triage ffuf <file.json>     Triage ffuf JSON (-of json) output
ptk triage subs <file>          Triage subdomain output (CSV / list / amass / subfinder)
ptk triage all <folder>         Run all three over a folder, unified report
ptk triage diff <old> <new>     Show only what changed between two scans
ptk triage rules [--dump]       Inspect / export the ruleset
```

### Generate inputs the tool understands

```bash
nmap -sV -sC -oX scan.xml 10.10.10.5
ffuf -w wordlist.txt -u http://target.com/FUZZ -o ffuf.json -of json
subfinder -d target.com -o subs.txt          # plain list
# or a CSV:  subdomain,ip,status   (missing fields OK)
```

### Triage a single tool

```bash
ptk triage nmap scan.xml
ptk triage ffuf ffuf.json
ptk triage subs subs.txt
cat subs.txt | ptk triage subs -            # read from stdin
```

### Unified report over an engagement folder

```bash
ptk triage all ./target-10.10.10.5
```

`all` auto-detects file types by extension and content (`.xml` → nmap,
`.json` → ffuf, `.txt`/`.csv`/`list` or names containing `sub`/`amass`/
`subfinder` → subdomains).

### Filters and output modes

```bash
ptk triage nmap scan.xml --only-high          # HIGH only (quick scan)
ptk triage nmap scan.xml --only-high-medium   # HIGH + MED
ptk triage nmap scan.xml --json               # machine-readable, pipe into jq
ptk triage nmap scan.xml --full               # also dump ALL parsed data
ptk triage nmap scan.xml --no-color           # disable ANSI color
ptk triage nmap scan.xml --notes notes.md     # append findings to a notes file
```

Color auto-disables when output is piped or redirected, so JSON/text stays clean.

### Diff mode

Re-scans happen constantly. `diff` shows only the delta so you read what's new:

```bash
ptk triage diff old_scan.xml new_scan.xml
ptk triage diff ./scan-day1 ./scan-day2      # folders also work
```

Diff understands meaningful transitions, not just text changes:

```
diff: 1 added, 1 changed, 9 removed

[HIGH]   shop.target.com   ~ CNAME became dangling (-> shop.herokuapp.com) — NEW possible subdomain takeover
[MED]    10.10.10.5:1433   + new open port — ms-sql-s Microsoft SQL Server 2019
[LOW]    10.10.10.5:22     ~ banner "OpenSSH 7.2p2" -> "OpenSSH 9.6p1"
[INFO]   10.10.10.5:3389   - port no longer open — was ms-wbt-server
```

A CNAME that *became* dangling is flagged **HIGH** (a fresh takeover window);
one that started resolving again is noted as a likely-closed window.

---

## What gets flagged

Every finding has a **severity** and a **one-line reason**. The engine refuses
to emit a finding without a reason — a flag you can't explain is noise.

| Severity | Meaning |
|----------|---------|
| `HIGH`   | Actionable now — real finding or very likely foothold |
| `MED`    | Worth looking at this scan — probable value, needs a human |
| `LOW`    | Note it — enumerate / check CVEs when you get to it |
| `INFO`   | Context only |

**nmap** — high-value services (SMB, RDP, WinRM, Kerberos, LDAP, MSRPC, MSSQL,
Redis, MongoDB, Elasticsearch, Jenkins, Tomcat, WebLogic, Docker/K8s APIs, …),
aged version banners (OpenSSH, Apache, IIS, PHP, the vsftpd 2.3.4 backdoor),
NSE script hits (anonymous/null access, default creds, `VULNERABLE`, disabled
SMB signing, weak TLS, writable shares), non-standard HTTP/SSH ports,
unprobed/guessed services, and unidentified open ports.

**ffuf** — interesting status codes (401/403/5xx/redirects, not just 200),
**response-size outliers** (entries that deviate from the modal "noise floor"
response size — the real finds buried in thousands of soft-404s), and a broad
set of sensitive path names (`.git`/`.svn`, `.env`, backups/archives, keys &
credentials, app config, admin/management panels, API & Swagger/GraphQL,
debug/actuator/phpinfo, installers, upload endpoints, existing webshell names).

**subdomains** — dangling CNAMEs (**HIGH**, possible takeover), non-prod &
sensitive naming (`dev`/`staging`/`test`/`internal`/`vpn`/`admin`/DevOps infra),
third-party cloud/CDN CNAME targets, resolves-but-no-web (candidate for a port
scan), and off-range IPs (outside your configured primary ranges).

**Cross-signal boost** — when independent rules reinforce each other on the same
target (e.g. a high-value service *and* an aged banner), severity is promoted
one level.

---

## Customizing rules

The ruleset is plain YAML. Dump the default (fully commented) and edit it:

```bash
ptk triage rules --dump > rules.yaml
# edit rules.yaml ...
ptk triage nmap scan.xml --rules rules.yaml
```

Inspect what's loaded:

```bash
ptk triage rules                      # summary of active rules
ptk triage rules --rules rules.yaml   # summary for a custom file
```

### Adding a pattern rule

Each pattern rule is a regex matched (case-insensitively) against one field of a
parsed item:

```yaml
patterns:
  - id: my-coldfusion
    field: banner          # service | product | version | banner | scripts
                           # | path | url | name | cname | redirect
    pattern: 'ColdFusion'  # Go RE2 regex; ^ $ \b supported
    severity: HIGH         # HIGH | MED | LOW | INFO
    reason: "Adobe ColdFusion — long history of deserialization / LFI RCE; check version"
    kinds: [host]          # optional: restrict to host | path | sub
    ports: [8500]          # optional (host only): only on these ports
```

`{match}` and `{target}` in `reason` are expanded with the matched text and the
finding's target.

### Tuning the built-in computed rules

These live under `builtins:` in the YAML and cover logic regex can't express:

```yaml
builtins:
  size_outlier: true
  size_outlier_pct: 0.25        # flag ffuf sizes deviating >=25% from baseline
  size_outlier_min_set: 15      # need >=15 paths before a baseline is trusted
  interesting_status: true      # treat 401/403/5xx/redirects as interesting

  nonstandard_http: true
  standard_http_ports: [80, 443, 8080, 8443, 8000, 8888]
  nonstandard_ssh: true
  standard_ssh_ports: [22]
  guessed_service: true         # nmap guessed the service, didn't probe it
  unknown_service: true         # open port, no identified service

  dangling_cname: true
  resolved_no_web: true
  offrange_ip: true
  primary_cidrs:                # set your target's ranges to light up outliers
    - 10.10.10.0/24

  combos: true                  # cross-signal severity boost
```

---

## Reliability

Recon tools get interrupted and output gets truncated. ptk **never crashes** on
malformed input — it degrades gracefully and tells you what it couldn't read
under a `warnings (possible coverage gaps)` section:

- **nmap**: truncated scans are salvaged at the `<host>` and even individual
  `<port>` level, so an interrupted single-host scan still yields every port
  that was fully written.
- **ffuf**: truncated JSON is salvaged record-by-record — every complete result
  object written before the cut is recovered.
- **subs**: unrecognized lines are skipped with a warning; it never silently
  drops a hostname it understood.

Because silently dropping a real finding is the worst failure mode for a recon
tool, coverage warnings are always printed (even under `--only-high`).

---

## Project layout

```
main.go                     entry point
cmd/                        cobra subcommands (nmap, ffuf, subs, all, diff, rules)
internal/
  model/                    normalized Item / Finding types (source-agnostic)
  parser/nmap|ffuf|subs/    raw output -> []Item   (+ truncation salvage)
  rules/                    the rule engine + embedded default_rules.yaml
  report/                   findings -> colored terminal / JSON
  diff/                     two scans -> ranked delta
testdata/                   sample fixtures (nmap XML, ffuf JSON, subs CSV)
```

The layering is deliberate: **parser → rule engine → presentation**. Parsers and
the engine stay stable while you extend the rules.

## Tests

```bash
go test ./...
```

Parsers are tested against fixtures (including truncated input), and the rule
engine is tested for correct severities, size-outlier behavior, dangling-CNAME
detection, off-range IPs, combo boosts, and the invariant that **no finding ever
has an empty reason**.

## Demo without a live target

```bash
go build -o ptk .
./ptk triage nmap testdata/sample_nmap.xml
./ptk triage nmap testdata/real_nmap.xml      # realistic AD domain-controller scan
./ptk triage ffuf testdata/sample_ffuf.json
./ptk triage subs testdata/sample_subs.csv
./ptk triage all  testdata
./ptk triage diff testdata/subs_old.csv testdata/subs_new.csv
```

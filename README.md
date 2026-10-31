# posint-scanner

Modular passive OSINT scanner for domains: subdomain discovery, DNS recon,
and host/service enrichment via pluggable sources (subfinder, Shodan, Qualys
SSL Labs, Qualys VMDR, DNS).

See `SCHEMA.md` for the SQLite data model.

## Quick start

`./launch.sh` handles first-run setup (deps, config.yaml, db init) and
either walks you through a scan interactively or forwards arguments
straight to the CLI:

```
./launch.sh                              # interactive: prompts for a domain and export format
./launch.sh scan example.com             # same as `uv run posint-scanner scan example.com`
./launch.sh export --format json --output results.json
```

## Manual setup

```
uv sync
cp config.example.yaml config.yaml   # fill in API keys
uv run posint-scanner db init
```

## Usage

```
uv run posint-scanner scan example.com
uv run posint-scanner scan --domains-file domains.txt
uv run posint-scanner export --format json --output results.json
uv run posint-scanner query --host api.example.com
```

A scan writes only to the database. Reports are produced on demand with
`export` (`--format obsidian | json | csv`, see **Export structure** below) or
the web UI's export zip.

External tools (nikto, trivy, theHarvester, ping, ...) run in throwaway
sandboxes (see **Tool sandbox** below) that can't write to disk; a run's raw
report is stored lzma-compressed in the `tool_outputs` table (latest per
domain, tool and target - a rescan replaces it, a run that finds nothing
removes it) and is downloadable from the domain page.

### Tool sandbox

Every external tool runs under [bubblewrap](https://github.com/containers/bubblewrap)
(`bwrap`), so a tool can't leave files behind - however it misbehaves or
gets killed:

- `/` is read-only to the tool, the database's directory included;
- `/tmp` is a fresh tmpfs holding its working dir, HOME and TMPDIR;
- it has its own PID namespace. When the sandbox ends, the kernel kills
  everything still running in it and frees the tmpfs, files left open
  included. If the scanner itself is killed, its sandboxes die with it.

A sandbox lives as long as one tool stage's workspace (a cloned repo stays
for both checkov and trivy), and the scanner parses the report in it before
it goes. At most 4 sandboxes run at once across every scan and process
sharing a data dir (lock files in `<db dir>/.posint-slots/`); a stage waits
for a free one. Each sandbox's tmpfs is in RAM and only takes what a tool
writes. A tool pushing it past its caps is killed:

```yaml
sandbox:
  size_mb: 1024       # per sandbox
  max_inodes: 200000
```

ping, searchsploit and subfinder are small and frequent, so they run in
one-shot sandboxes with a 16 MB tmpfs that don't count against the 4.

Without a working bwrap no external tool runs: each stage is skipped as if
its binary were missing, the log says why at startup, and the web UI shows a
banner. Check a setup with:

```
posint-scanner sandbox-check --db /data/posint.db
```

In Docker, bwrap needs `security_opt: [seccomp=unconfined,
apparmor=unconfined, systempaths=unconfined]` (already in
`docker-compose.yml`; no capabilities are added). If `sandbox-check` still
fails:

- SELinux hosts: add `label=disable` to `security_opt`.
- Hosts that restrict unprivileged user namespaces (Ubuntu 23.10+:
  `kernel.apparmor_restrict_unprivileged_userns=1`), or kernels without
  them: add `cap_add: [SYS_ADMIN]`. bwrap then works without a user
  namespace. Tools still run with every capability dropped.

Outside Docker, ping (which gets no capabilities in the sandbox) needs
unprivileged ICMP sockets - Docker allows them in containers by default:
`sysctl -w net.ipv4.ping_group_range="0 2147483647"`.

The data dir and the tool cache must not be under `/tmp`, which the sandbox
covers with its own tmpfs.

trivy and wpscan scan against downloaded vulnerability DBs that a scan never
updates. Fetch or refresh them (into `<db dir>/.posint-cache/`, or
`$POSINT_CACHE_DIR`) with:

```
uv run posint-scanner update-dbs
```

Qualys VMDR active scan-triggering is disabled by default; pass
`--authorize-scans` to `scan` to enable it. Only do this against
infrastructure you are authorized to scan.

### Re-scanning (automatic continuation)

Re-running a scan builds on the existing database (every stage upserts, so
prior results are preserved and refreshed). When the domain is **already in
the database**, the scan automatically continues the previous one: after
re-checking the domain it prunes what's no longer valid - DNS mappings the
target no longer returns, and IP addresses (with their services and results)
that nothing resolves to anymore.

```
posint-scanner scan example.com      # first run: builds the dataset
posint-scanner scan example.com      # again: revalidates and prunes stale data
```

Pruning is driven by which records this run re-observed, with a guard that
leaves a hostname's mappings alone when it resolved to nothing this run (so a
transient DNS/resolver failure can't erase valid data). Hostnames themselves
are kept - a discovery source being unavailable isn't proof a name is gone. A
first-ever scan of a domain has nothing to prune.

## Web UI

A browser dashboard to launch scans and read reports (no Obsidian needed - the
notes render as HTML pages with working links, plus a security overview with
critical findings, exposed sensitive services and CVE tables).

A running scan reports the stage it's on (discovery, resolution, enrichment,
fingerprint, CVE lookup, …) on its status page and in the dashboard's scan
list, and can be stopped with a **Cancel** button - cancellation is
cooperative (it stops at the next stage boundary) and keeps whatever was
gathered so far.

### Resuming interrupted scans

Scan jobs are stored in the DB, together with the work each has finished:
every completed stage, the slow per-target runs inside a stage (fingerprint
per service; php2shell, CVE lookup, nuclei, nikto and wpscan per IP; trivy
per image/repo; prowler/scoutsuite per provider), every source call, and the
TLD siblings it queued. A scan still running when the server stops
(container restart, crash, `docker compose down`) shows up as
**interrupted** and, by default, `serve` resumes it on the next start;
`serve --no-resume` only lists it, with a **Resume** button. Cancelled and
failed scans get the same button.

A resumed scan continues where it stopped: finished stages and tool runs are
skipped, source calls answered earlier in the job aren't repeated (no API
credits spent twice, even with *fresh*), and only the unit of work that was
cut off is redone. Two exceptions run again in full when cut off midway:
discovery (its hostnames are stored only once every discovery source is done)
and the resolution + netblock sweep stage (its stale-mapping pruning needs a
complete pass). Hostnames enrichment would have related to an already-answered
call are not chased again. Once a job completes, its checkpoints are dropped.

The dashboard can **delete** a domain with everything scanned for it (IPs
another domain still resolves to are kept; refused while a scan runs), and
**download everything** (or the selected domains) as one zip: `results.json`,
`services.csv`, the Obsidian vault and a copy of the SQLite database (which
carries the raw tool reports).

```
pip install -e '.[web]'                  # optional web extra (FastAPI/uvicorn/jinja2)
posint-scanner serve                     # http://127.0.0.1:8000
posint-scanner serve --db posint.db --host 127.0.0.1 --port 8000
```

Binds to localhost by default: the UI can start active scans, so only expose
it more widely on a network you control.

### Settings: global proxy

The **Settings** page sets a SOCKS5 proxy (`socks5h://[user:pass@]host:port`,
e.g. Tor or `ssh -D`) that **every** scan connection goes through - or isn't
made. Stored in the DB, so it applies to web and CLI scans alike; a scan
refuses to start if the proxy is unreachable. **Test proxy** checks an
unsaved proxy end to end (reachable, HTTPS through it with the exit IP, DNS
through it) without saving or activating it.

- HTTP(S) requests and tool subprocesses: via `ALL_PROXY`/`HTTPS_PROXY`
  (hostnames resolve at the proxy); nuclei, subfinder and wpscan get their own
  proxy flag.
- Port scan: TCP connections tunnelled through the proxy.
- DNS: sent over TCP through the proxy to a configurable DNS server
  (default `1.1.1.1`); UDP DNS is blocked.
- Skipped while proxied (can't be tunnelled): ping (ICMP), Nikto, takeover,
  theHarvester, php2shell-checker.

### Settings: API keys

The **Settings** page also sets per-source API keys and credentials
(Shodan/Censys/LeakIX/… keys, the NVD key, the WPScan token) without touching
`config.yaml`. Stored in the DB, they apply to web and CLI scans against it,
and are merged in only where a source isn't already keyed elsewhere -
precedence is `OSINT_<SOURCE>_<FIELD>` env var > Settings page > config.yaml.
Stored values are never shown back: leave a field blank to keep it, type to
replace it, or tick **clear** to remove it. A source with no credential is
skipped at scan time. Keys are stored in plain text in the scan database.

### Docker

```
docker compose up --build                # http://127.0.0.1:8000
```

The SQLite DB and an optional `config.yaml` persist in `./data` (mounted at
`/data`). The trivy/wpscan DBs (~3GB) are downloaded into
`./data/.posint-cache` on first start, which takes a few minutes; refresh them
with `docker compose exec posint-scanner posint-scanner update-dbs --db
/data/posint.db`. API keys can go in `./data/config.yaml` or be
passed as `OSINT_*` env vars (uncomment `env_file` in `docker-compose.yml`).
The compose port is pinned to `127.0.0.1:8000` for the same reason as above.

## Netblock sweep

After resolving all discovered hostnames, `scan` looks up the ASN
announcing each known IP (Team Cymru's DNS whois) and every prefix that ASN
announces (RIPEstat), then reverse-PTR-sweeps those prefixes - not just a
single /24 - keeping any hostname whose PTR record belongs to the target
domain. This catches hosts with no public TLS cert and no naming link to
anything else discovered, anywhere in the target's own address space, not
just next to an IP you already happen to know about.

When ASN lookup can't pin down a dedicated block for an IP - lookup fails,
or (see below) the ASN's prefix turns out to be way too big - it falls back
to that IP's own /24 plus its immediate neighbors above and below, since
allocators commonly assign contiguous /24s to the same organization.

Each address is queried against a baseline list of public resolvers
(default **1.1.1.1, 8.8.8.8, 9.9.9.9** - overridable with
`--netblock-sweep-resolvers`) and, if the target's own nameserver could be
resolved, **that nameserver too** - a target that manages its own
reverse-DNS zone may have records its own authoritative server sees that a
public resolver's cache doesn't, and different public resolvers can
disagree too. Fully passive (plain DNS queries and one HTTP GET to a public
BGP-data service), no scanning of the target itself.

An ASN can announce far more address space than a single /24 (a real
example: one target's ASN spanned ~30,000 addresses across 7 prefixes,
vs. 256 for the old /24-only sweep) - `--netblock-sweep-max-addresses`
(default 20,000) caps total addresses swept per domain so a target hosted
on a huge cloud-provider ASN doesn't turn into an unbounded sweep of
unrelated infrastructure. A prefix confirmed to contain a known IP is
normally swept in full even if that alone exceeds the cap - **unless the
confirmed prefix itself is bigger than the cap**, which is a strong signal
it's shared/third-party infrastructure (a CDN, cloud provider, a big
transit ASN) rather than something the target owns outright; in that case
only the /24-plus-neighbors fallback above is swept, not the oversized
prefix. (Seen for real: one IP's ASN prefix was 3.5 million addresses -
sweeping that in full would have taken hours and mostly queried unrelated
infrastructure.) The cap otherwise only limits how many additional,
unconfirmed same-ASN prefixes get explored. Disable the whole stage with
`--no-netblock-sweep`.

## Concurrency

Everything in this tool is I/O-bound (DNS, HTTP, subprocess calls) - no
CPU-bound work exists anywhere, so it's threaded, not multiprocessed.

- `--workers` (default 5) - discovery/enrichment thread pool size, per
  domain. Kept modest by default since these stages call external
  rate-limited APIs (Shodan, Censys) where more concurrency doesn't help
  and can hurt; raise it if your API plans support more throughput.
- `--netblock-sweep-workers` (default 150) - the netblock sweep's shared
  thread pool size. All networks being swept for a domain (a fallback /24
  plus neighbors, or several same-ASN prefixes) share one pool rather than
  each getting its own, so this is one bounded, predictable number instead
  of nested pools multiplying together.
- `--max-concurrent-domains` (default 4) - how many domains run
  concurrently when scanning a `--domains-file` batch. Each domain's full
  pipeline is otherwise independent; `Database` is thread-safe (a lock
  guards every method) and the NVD client is shared and lock-protected
  across all concurrently-running domains, since NVD's rate limit is
  enforced against this machine's IP regardless of how many client objects
  exist internally. A failure in one domain's pipeline is logged and only
  costs that domain - the rest of the batch continues.

Every per-domain stage already opens its own thread pool, so concurrent
domains multiply those pools together - e.g. 4 domains simultaneously
mid-netblock-sweep could mean up to `4 x 150` threads for that stage alone.
Still cheap for threads that spend nearly all their time blocked on a
socket, but worth knowing the shape of it before cranking every number up.

## Port verification

Shodan, Censys, LeakIX and the other enrichment sources report the ports
their crawlers saw, sometimes months ago. Right after enrichment, `scan`
TCP-connects every reported TCP port (no data sent; one retry) and removes
the services that don't accept the connection, so fingerprinting, the CVE
lookup and the scanners only work on ports open now. The sources' own
reports stay in `results`, and each IP gets a `port_verify` result listing
what was open and what was dropped. UDP services aren't checked. If no port
at all answers, the scanner assumes its own connectivity is the problem and
keeps everything. An active stage: on by default, `--no-verify-ports` (or
`--no-active`) turns it off.

## Vulnerability lookup

After enrichment, `scan` looks up CVEs for whatever product/version pairs
were actually detected (from Shodan, Censys, or the `portscan` source), via the
free NVD (NIST) API - no key required, though a free key
(nvd.nist.gov/developers/request-an-api-key, configured under `nvd:` in
config.yaml) raises the rate limit from 5 to 50 requests per 30s. Fully
passive: only queries NIST's public database, never touches the target.

If a source already gave a real CPE (Shodan's `cpe23` field, for example),
that's used directly; otherwise a best-effort CPE is guessed from the
product name (assuming vendor == product, which works for a lot of
well-known open-source software but not universally) and flagged as
guessed in the stored result. NVD's CPE-based matching has uneven coverage
- plenty of real product/version combinations have zero recorded CVEs in
NVD's data even when vulnerabilities exist, so treat this as best-effort
enrichment on top of whatever versions were detected, not a complete
vulnerability database. Disable with `--no-vuln-lookup`.

Only CVEs that state the detected version as affected are kept: NVD's CPE
match also returns CVEs that list the product with no version or range
("all versions") or only as the platform another component runs on (e.g.
WordPress for every WordPress plugin CVE), which say nothing about the
version running. The affected version/range is shown in the IP page's
Affected column. Each scan replaces an IP's stored CVEs, unless NVD didn't
answer (rate limit), in which case the earlier ones stay.

If `searchsploit` (the offline [Exploit-DB](https://gitlab.com/exploit-database/exploitdb)
CLI) is on `PATH`, each found CVE is also checked against the local
Exploit-DB copy and annotated with any published exploits (title + EDB
link) - a real "how exploitable is this" signal, shown as an Exploit column
on the IP page and carried into the JSON export. Purely local: no network
call, nothing sent to the target. Absent binary = silently skipped.

## Nuclei active scan

[Nuclei](https://github.com/projectdiscovery/nuclei) template-scans the web
services the fingerprint stage confirmed, matching them against its library of
CVE/misconfiguration/exposure templates. Findings (severity, template, matched
URL, any CVE ids) are stored per IP, shown in a **Nuclei findings** table on
the IP page and included in the JSON export.

This is **active and intrusive** - it sends crafted requests to the target -
so it is **off by default** and runs only with `--nuclei` (CLI) or the
dashboard's *nuclei scan* box, and only against hosts you are authorized to
test. It needs the `nuclei` binary on `PATH`; when absent the stage is skipped
with a warning. It scans whatever the fingerprint stage found, so run it with
fingerprinting on (the default).

**Templates.** Nuclei uses its own template directory by default; point
elsewhere with `nuclei.templates_dir` in config (or `OSINT_NUCLEI_TEMPLATES_DIR`).
To pull the wider community set, use [`cent`](https://github.com/xm1k3/cent),
which aggregates community template repos into a directory:

```
go install github.com/xm1k3/cent@latest     # build the cent binary
cent init                                    # writes ~/.cent.yaml (repo list)
cent -p ~/nuclei-community                    # aggregate the community templates
```

The Docker image does exactly this at build time (cent built via `go install`
in a Go build stage, templates aggregated into `~/nuclei-community`) and points
the scanner there via `OSINT_NUCLEI_TEMPLATES_DIR`; build with
`--build-arg INSTALL_NUCLEI=false` to skip nuclei and the template download for
a slimmer image.

## Cloud scanning

Two opt-in stages bring in dedicated cloud-security tooling
([Trivy](https://github.com/aquasecurity/trivy),
[Checkov](https://github.com/bridgecrewio/checkov),
[Prowler](https://github.com/prowler-cloud/prowler),
[ScoutSuite](https://github.com/nccgroup/ScoutSuite)) on top of the passive
recon. Each tool is wrapped thinly and **skipped with a warning when its binary
isn't on PATH**, so the stages are safe to leave enabled. Findings (tool,
severity, check id, resource) are stored per domain, shown in a **Cloud & IaC
findings** table on the domain page, and included in the JSON export.

### `--cloud-scan` - artifact scanning (credential-free)

Inspects *artifacts the passive stages already surfaced*, never the target's
own infrastructure - no credentials needed:

- **Public GitHub repos.** The public repos the `github` source found naming
  this domain are shallow-cloned and scanned with **Checkov** (IaC misconfig -
  Terraform/CloudFormation/K8s/Dockerfiles) and **`trivy fs`** (vulnerable
  dependencies, secrets, misconfig). Add extra repos with `cloudscan.repos`.
- **Public container images.** **`trivy image`** scans images an exposed
  registry listed (via the `container_exposure` source), any in
  `cloudscan.images`, and names guessed as `<org>/<label>` /
  `ghcr.io/<org>/<label>` for each org in `cloudscan.guess_image_orgs`.

Needs the `trivy` and/or `checkov` binaries (and `update-dbs` for trivy).
Repos are cloned one at a time and each clone is deleted once scanned; a clone
growing past `cloudscan.max_clone_mb` (default 500) is killed and skipped.
Bounded by `cloudscan.max_repos` / `max_images` and `clone_timeout_seconds`.

### `--cloud-audit` - cloud account auditing (authenticated)

Runs **Prowler** and **ScoutSuite** against the providers in
`cloudscan.providers` (`aws`/`azure`/`gcp`/`kubernetes`). These need
**credentials for the target's own cloud account**, which the vendor CLIs read
from the ambient environment the usual way (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`,
`~/.aws`, `gcloud`/`az` logins, `KUBECONFIG`, ...) - this tool never handles
secrets itself. **Only for accounts you are authorized to audit.** Needs the
`prowler` and/or `scout` binaries. In the tool sandbox HOME is a throwaway
dir, so `~/.aws`, `~/.kube/config`, `~/.config/gcloud` and `~/.azure` are
passed by their env vars (`AWS_CONFIG_FILE`, `KUBECONFIG`, ...) and are
read-only: a login that must refresh tokens on disk won't persist them.

Both stages are off by default; enable per scan with `--cloud-scan` /
`--cloud-audit` (CLI) or the dashboard's *cloud artifact scan* / *cloud account
audit* boxes (never remembered in localStorage, like the other active toggles).
The Docker image installs all four tools (build with
`--build-arg INSTALL_CLOUDSCAN=false` to skip). Configure under `cloudscan:` -
see `config.example.yaml`.

## Web app & subdomain-takeover scans

Four more stages, each a thin wrapper around a dedicated tool (gracefully
skipped when its binary isn't on `PATH`):

- **`--nikto`** runs the [Nikto](https://github.com/sullo/nikto) web-server
  scanner against every resolved web service (dangerous files, outdated
  components, unsafe configuration).
- **`--wpscan`** runs [WPScan](https://github.com/wpscanteam/wpscan) against
  every resolved web service - a fast no-op on non-WordPress sites. Set
  `webscan.wpscan_api_token` (or `OSINT_WPSCAN_API_TOKEN`) to unlock its
  vulnerability database; without it, versions are enumerated but no CVEs.
- **`--takeover`** checks every discovered hostname for a dangling, claimable
  service (subdomain takeover) with
  [takeover](https://github.com/edoardottt/takeover) and its
  `can-i-take-over-xyz` fingerprints. This is the subdomain-takeover capability
  [Sn1per](https://github.com/1N3/Sn1per) would otherwise add - takeover covers
  it without pulling in Sn1per's root-hungry, pipeline-overlapping framework.
- **php2shell** (on by default; `--no-php2shell` or the dashboard box turns it
  off, and it follows `--no-active` / `defaults.active` like the tech
  fingerprint) runs
  [php2shell-checker](https://github.com/openai/php2shell-checker) against
  every web service: one `HEAD` request reading the PHP version from
  `X-Powered-By` / `Server`, flagged *critical* when it's at or below the
  php2shell fix for its branch. Every disclosed stable PHP version is also
  looked up in NVD (`cpe:2.3:a:php:php:<version>`, distro suffixes like
  `-1ubuntu1` stripped) by the CVE lookup that runs right after - so this stage
  adds PHP CVEs even where the fingerprint stage didn't see the version.
  Needs Node.js and a `phpcheck` wrapper on `PATH`
  (`exec node /path/to/php2shell-checker/phpcheck.js "$@"`); the Docker image
  ships both. TLS certificates aren't validated (self-signed and expired certs
  are common on exactly the hosts worth checking), like the other scanners. A
  hidden header means no finding - not that the host is patched.

Unlike the Nuclei stage (which scans only fingerprint-*confirmed* URLs), the
web-app scanners run against every resolved `host:port`. Nikto/WPScan findings
(and php2shell's) are stored per IP and shown in a **Web app scan findings**
table on the IP page; takeover findings are stored per hostname and shown in a **Subdomain
takeover** table on the domain page. All flow into the JSON export. Nikto,
WPScan and takeover are active/intrusive, so off by default - enable per scan
with the flag or the matching dashboard box (never remembered in
localStorage), and only against hosts you are authorized to test. Configure under `webscan:` - see
`config.example.yaml`.

## Export structure

The Obsidian report is flat folders per entity type, not nested by DNS
depth - relationships are frontmatter properties, wikilinks, and tags
instead, since that supports cross-cutting queries (by port, by source, by
finding) that a folder tree can't:

```
vault/
  Domains/example.com.md        - apex domain, links to its hostnames
  Hosts/api.example.com.md      - one flat note per hostname: parent domain,
                                   resolved IPs, every source's results
  IPs/1.2.3.4.md                 - one note per unique IP: services, results,
                                   backlinked from every hostname resolving to it
```

Regenerated (overwritten) on every export - it's a view of the SQLite
database, never hand-edited or read back.

## Sources

| source | category | role | notes |
|--------|----------|------|-------|
| `subfinder` | passive | discovery | shells out to the `subfinder` CLI; skipped with a warning if not on `PATH` |
| `dnsrecon` | passive | discovery + enrichment | reverse PTR lookups, AXFR zone-transfer attempts, NS/MX/TXT/SOA records |
| `crtsh` | passive | discovery | certificate-transparency search; crt.sh is flaky, failures are retried then skipped |
| `certspotter` | passive | discovery | Cert Spotter certificate-transparency search - a second CT feed for when crt.sh is down. Keyless at a small hourly allowance, optional `api_key` for more |
| `wayback` | passive | discovery | hostnames from the Wayback Machine's capture index (incl. historical hosts); slow, 7-day TTL |
| `commoncrawl` | passive | discovery | hostnames from the latest Common Crawl URL index; 7-day TTL |
| `hackertarget` | passive | discovery + enrichment | host search; reverse IP per IP. Keyless at 50/day (shared by both), optional `api_key` for more |
| `otx` | passive | discovery + enrichment | AlienVault OTX passive DNS for the domain and per IP; free account key required |
| `virustotal` | passive | discovery + enrichment | subdomains (paged); IP resolutions per IP. Free key: 4 req/min, 500/day by default |
| `securitytrails` | passive | discovery | SecurityTrails subdomain list; free key: 50/month by default |
| `fullhunt` | passive | discovery | FullHunt subdomains; free key: 100/month by default |
| `netlas` | passive | discovery | Netlas DNS domains search; keyless at a low allowance, free key: 50/day by default |
| `urlscan` | passive | discovery + enrichment | urlscan.io scan search: pages under the domain; scans served from each IP. Keyless, optional key |
| `greynoise` | passive | enrichment | GreyNoise Community: is the IP a known scanner / benign service. Keyless, optional key |
| `ipinfo` | passive | enrichment | geolocation, org/ASN, PTR hostname. Keyless, optional token |
| `abuseipdb` | passive | enrichment | abuse-report score/history and associated hostnames; free key: 1000/day by default |
| `leakix` | passive | enrichment + collection | LeakIX index of exposed services and leaks (open DBs, exposed `.env`/`.git`, no-auth access) per IP and per domain, plus the domain's subdomains. Severity-graded findings. Free key required, ~1 req/s |
| `grayhatwarfare` | passive | collection | queries GrayHatWarfare's index of already-public cloud buckets by the domain's label (passive counterpart to `bucketsearch`); findings stored as public cloud assets. Free key required. Candidates - confirm ownership |
| `bucketsearch` | active | collection | guesses cloud storage bucket names (domain label + suffixes, or names you supply) and checks S3/GCS/Azure for public exposure. Off by default; never reads bucket contents |
| `rdap` | passive | collection | the domain's registration record: registrar, registered/expiry/last-changed dates, EPP status, nameservers, DNSSEC. Contact entities are dropped. Keyless, 7-day TTL |
| `entra_id` | passive | collection | Microsoft Entra ID / M365 tenant: tenant ID, region, managed vs federated (+ ADFS sign-in URL), seamless SSO, branding, every domain in the same tenant (fed back as candidate domains), `.onmicrosoft.com` name, Defender for Identity, M365 DNS records. Keyless, 7-day TTL |
| `email_auth` | passive | collection | email-spoofing posture from DNS: grades SPF (`all` qualifier, >10-lookup permerror, duplicate records), DMARC (`p=none`/missing, `sp`, `pct`, `rua`), DKIM (common selectors) and CAA. Reports whether the domain is spoofable. Keyless, 7-day TTL, DNS-only |
| `lookalike` | passive | collection | typosquat/homoglyph permutations of the domain (à la dnstwist), resolved against public resolvers; reports the registered ones (A/AAAA or MX) as possible impersonation domains. Keyless, 7-day TTL. Off by default (hundreds of DNS lookups). Never scans the look-alikes - they aren't yours |
| `origin_ip` | passive | collection | de-cloaks a CDN/WAF-fronted domain (à la HatCloud): detects Cloudflare/Fastly fronting, then reports non-CDN origin IPs the zone's own DNS leaks (MX, SPF `ip4:`/`a:`, direct-connect subdomains). Keyless, 7-day TTL, DNS-only. Candidate IPs kept in domain data (not auto-scanned) |
| `rapiddns` | scrape | discovery | scrapes rapiddns.io's subdomain page (robots.txt allows it); opt-in |
| `dnsbrute` | passive | discovery | resolves `<word>.<domain>` from a wordlist (e.g. SecLists) against public resolvers, with wildcard filtering. Off by default; needs a wordlist. 7-day TTL |
| `fullhunt_web` | scrape | discovery | scrapes FullHunt's public search page; keyless stand-in for `fullhunt` |
| `shodan` | passive | enrichment | keyed by IP; open ports, service banners/versions, and per-service vulnerability data (CVEs, CPEs) if your plan includes it. 7-day TTL |
| `censys` | passive | enrichment | keyed by IP; open ports/banners/versions, independent of Shodan's plan tier - needs a free Censys account (`censys.io`). 7-day TTL |
| `qualys_ssllabs` | passive | enrichment | keyed by hostname (SNI); free, no API key |
| `qualys_vmdr` | passive | enrichment | reads existing asset/vuln data always; triggering a new scan requires `--authorize-scans` |
| `ping` | active | enrichment | keyed by IP; sends ICMP straight to the target |
| `portscan` | active | enrichment | keyed by IP; TCP connect scan + banner grab across ~40 common ports. Independent fallback for open ports/versions when Shodan/Censys have no data |
| `container_exposure` | active | enrichment | keyed by IP; detects unauthenticated container/orchestration control planes (Docker API, Kubernetes API, kubelet, registry) and lists an open registry's images (fed to the `--cloud-scan` Trivy stage). Off by default; only reads (never execs/pulls) |
| `snmp` | active | enrichment | keyed by IP; checks UDP 161 with an SNMPv3 engine-discovery request (no credentials) and a v2c/v1 GET of the system group per community (`communities: [public]`, env `OSINT_SNMP_COMMUNITIES=public,private`). Records 161/udp when an agent answers and analyzes what it discloses: the OS from sysDescr (on Linux the exact running kernel, plus the distro/release and package its build implies), vendor, MAC/IP from the engine ID, uptime/last boot, contact/location. Flags a default community, cleartext v1/v2c and v3 engine disclosure. Shodan's SNMP banners get the same analysis on the IP page. Off by default (trying a community is a login attempt); skipped behind the SOCKS5 proxy (UDP) |
| `shodan_web` | scrape | discovery + enrichment | scrapes shodan.io's public pages; keyless stand-in for `shodan` (see fallbacks below). Its domain-page lookup runs against a robots.txt disallow |
| `subdomainsfinder` | passive | discovery | stub - no documented API, always raises; disabled unless explicitly enabled |
| `theharvester` | passive | collection | email addresses (and in-scope hostnames, fed back) from the `theHarvester` CLI; `backends` is its `-b` list (default `emails`: every address-yielding backend - search engines, CT logs, OSINT APIs; keyed ones read theHarvester's own `api-keys.yaml`). Skipped with a warning if not on `PATH`. 7-day TTL |
| `hunter` | passive | collection | Hunter.io domain search: addresses with name, title, confidence and a source page, plus the org's address pattern. Free key: 25/month by default, 10 addresses per search (`limit` for paid plans) |
| `tomba` | passive | collection | Tomba.io domain search (Hunter-style). Needs `api_key` + `api_secret`; free: 25/month by default |
| `pgp_keyserver` | passive | collection | addresses in PGP key user IDs on keyserver.ubuntu.com (incl. long-gone staff). Keyless, 7-day TTL; skipped for domains with so many keys the keyserver errors |
| `github` | passive | collection + enrichment | searches public GitHub code for the domain's hostnames (one apex search covers subdomains) and each IP: files naming a target become "reference" exposures (and feed hostnames back), and every kept file is scanned for secrets (built-in rules + `gitleaks` if on `PATH`, and `trufflehog` with `--no-verification` when enabled; never verified). Needs a token (any PAT). Post-filters tokenized false positives; drops forks and docs/vendored files (unless a file holds a secret); skips private/CDN/shared IPs. Secret values are stored in full. 7-day TTL |

### Choosing which sources run

Each source has a category: **passive** (queries resolvers / third-party
APIs), **scrape** (parses a service's public HTML instead of a documented API
- ToS/robots-sensitive) or **active** (sends traffic straight to the target).
By default passive and active sources run and scrapers don't. Per source,
most specific wins:

1. `--source NAME` / `--no-source NAME` (repeatable)
2. `--no-active` (also turns off the port-verification and tech-fingerprint
   stages)
3. `sources: {NAME: {enabled: true|false}}` in config.yaml
4. the source's own default (e.g. the `subdomainsfinder` stub is off)
5. `defaults: {passive: true, scrape: false, active: true}` in config.yaml

`--sources a,b` still narrows a run to just those names. `--ping/--no-ping`,
`--scan-ports/--no-scan-ports` and `--shodan-web` still work as deprecated
aliases for `--source`/`--no-source`. The web UI shows one checkbox per
source, pre-checked from config.

**Fallbacks.** A `*_web` scraper declares the API source it stands in for.
It's skipped when that sibling is enabled and has its key configured, unless
forced with `force: true` in its config or named with `--source`.

### Related hostnames and candidate domains

Enrichment sources often know other names for a target - reverse-IP
neighbours (HackerTarget, VirusTotal, OTX, urlscan), PTR names (IPinfo),
hostnames Shodan/AbuseIPDB associate with it. After enrichment:

- names **under the scanned domain** that aren't known yet are added,
  resolved and enriched in one follow-up pass (bounded: names that pass
  surfaces are stored but not chased further);
- a **TLD sibling** - the same name under another public suffix
  (`brand.com` -> `brand.net`, `brand.co.uk`) - is in scope: it's scanned as
  its own domain in the same run. Private suffixes (`brand.github.io`) don't
  count;
- **anything else** is reduced to its registrable domain
  (`shop.brand.co.uk` -> `brand.co.uk`) and recorded as a *candidate domain*
  on the scanned domain - shown on its web UI page with a one-click *Scan*
  button, in the Obsidian domain note and the JSON export. Candidates are
  **never scanned automatically**: shared hosting makes reverse-IP data
  noisy, and a candidate may belong to someone else. A target related to
  more than 25 other domains is treated as shared hosting and yields none.

### Quotas: TTL, budgets, rate limits

Every source call is governed (see `governor.py`), with limits per source
that any source can override in config:

```yaml
sources:
  shodan:
    api_key: "..."
    ttl_days: 7              # skip IPs Shodan answered for in the last 7 days (0 = always query)
    daily_budget: 100        # max calls per rolling 24h
    monthly_budget: 1000     # max calls per rolling 30 days
    requests_per_minute: 60  # pacing
```

Usage is recorded in the database (`source_calls`), so budgets and TTLs hold
across runs. A source that hits its budget is skipped for the rest of the
run. `--fresh` (or the web UI's *fresh* box) ignores TTLs for one run.

## Configuration

`sandbox:` caps each tool sandbox (see **Tool sandbox**). Every source lives under one `sources:` map; each field can also be set via
`OSINT_<SOURCE>_<FIELD>` (e.g. `OSINT_SHODAN_API_KEY`,
`OSINT_SHODAN_WEB_ENABLED=true`). Old top-level sections (`shodan:`,
`censys:`, `qualys_vmdr:`) keep working. See `config.example.yaml`.

Keyed sources with no key configured are skipped once per run with a
warning. Every keyed/metered source defaults to a 7-day TTL.

## Adding a new source

1. Create `src/posint_scanner/sources/my_source.py`, subclass `Source`
   (`sources/base.py`), set `name` and `category`, and implement any of
   `discover` (domain -> hostnames), `enrich` (IP/hostname -> data) and
   `collect` (domain -> domain-level data, incl. `cloud_assets`).
2. If it takes keys/options: subclass `SourceSettings` with the fields, set
   `settings_model`, override `from_settings` and `is_configured`. Metered
   APIs should set `ttl_days = DEFAULT_TTL_DAYS` and any known free-tier
   limits (`requests_per_minute`, `daily_budget`, `monthly_budget`).
3. Add the class to `SOURCE_CLASSES` in `registry.py`.

Config, env vars, CLI flags and the web UI toggles pick it up from there.

Parsers are tested against response bodies under `tests/fixtures/<source>/`
(captured from the real service where possible - see its README). A scraper
should raise `ScrapeParseError` when a page fetched fine but lacks the
structure it parses, so markup drift is reported instead of looking like "no
data". `pytest -m live` runs canaries against the real endpoints (keyed ones
need `OSINT_<SOURCE>_API_KEY` set).

## Development

```
uv sync --group dev
uv run pytest
uv run mypy src/posint_scanner
```

# Data model

SQLite is the source of truth for a scan (`posint.db` by default). Obsidian
markdown, JSON, and CSV are all generated *views* of this database via
`posint-scanner export`, regenerated on every export run - they're never
edited by hand and never read back in.

## Why hostnames and IPs are separate

A DNS name (`api.example.com`) and a machine (an IP address) aren't the same
thing: a single IP can answer for many unrelated hostnames (shared hosting,
CDN edges, load balancers), and a hostname can resolve to multiple/changing
IPs over time. Modeling them as one entity would make that relationship
unrepresentable. So `hostnames` and `ip_addresses` are independent tables,
connected by the `resolutions` many-to-many join table. Services (open
ports) attach to the IP, not the hostname, since a service runs on a
machine.

## Tables

### `domains`
The apex domains fed into a scan.

| column     | type | notes                  |
|------------|------|-------------------------|
| id         | INTEGER PK | |
| name       | TEXT NOT NULL UNIQUE | normalized (see `normalize.py`) |
| added_at   | TEXT NOT NULL | ISO-8601 timestamp |

### `hostnames`
Discovered DNS names (subdomains) belonging to a domain.

| column              | type | notes |
|---------------------|------|-------|
| id                  | INTEGER PK | |
| domain_id           | INTEGER NOT NULL REFERENCES domains(id) | apex domain this hostname belongs to |
| name                | TEXT NOT NULL UNIQUE | e.g. `api.example.com` |
| parent_hostname_id  | INTEGER REFERENCES hostnames(id) | best-effort DNS-hierarchy parent, inferred at scan time (see `orchestrator.infer_parent_hostname`); NULL if no intermediate parent was independently discovered |
| first_seen          | TEXT NOT NULL | set on first discovery |
| last_seen           | TEXT NOT NULL | bumped every time a source re-discovers it |

### `ip_addresses`
Unique IPs, independent of any one hostname.

| column     | type | notes |
|------------|------|-------|
| id         | INTEGER PK | |
| address    | TEXT NOT NULL UNIQUE | |
| first_seen | TEXT NOT NULL | |
| last_seen  | TEXT NOT NULL | |

### `resolutions`
Many-to-many join: which hostnames currently/historically resolve to which IPs.

| column       | type | notes |
|--------------|------|-------|
| hostname_id  | INTEGER NOT NULL REFERENCES hostnames(id) | |
| ip_id        | INTEGER NOT NULL REFERENCES ip_addresses(id) | |
| first_seen   | TEXT NOT NULL | |
| last_seen    | TEXT NOT NULL | |

Primary key: `(hostname_id, ip_id)`.

### `services`
Open services observed on an IP.

| column     | type | notes |
|------------|------|-------|
| id         | INTEGER PK | |
| ip_id      | INTEGER NOT NULL REFERENCES ip_addresses(id) | |
| port       | INTEGER NOT NULL | |
| protocol   | TEXT NOT NULL DEFAULT 'tcp' | |
| banner     | TEXT | product name, if a source provided one (e.g. `nginx`) |
| version    | TEXT | version string, if a source provided one (e.g. `1.18.0`) |
| cpe        | TEXT | Common Platform Enumeration string, if a source provided one (e.g. Shodan's `cpe23`), used to look up CVEs via NVD |
| first_seen | TEXT NOT NULL | |
| last_seen  | TEXT NOT NULL | |

`version` and `cpe` were added after the initial schema -
`Database.init_schema()` adds them in place via `ALTER TABLE` for existing
databases, no data loss. Unique on `(ip_id, port, protocol)`.
Vulnerability data itself (CVEs, CVSS scores) isn't normalized into its own
column/table - it's the NVD lookup stage's structured output, so it lives in
the matching `results` row for that IP instead, keyed by `source: "nvd"`.

### `results`
Generic bucket for whatever a source returns about a target. New sources
never require a schema migration - they just write here.

| column      | type | notes |
|-------------|------|-------|
| id          | INTEGER PK | |
| source      | TEXT NOT NULL | e.g. `shodan`, `censys`, `qualys_ssllabs`, `qualys_vmdr`, `dnsrecon`, `nvd`, `portscan`, `ping` |
| target_type | TEXT NOT NULL | `"ip"`, `"hostname"` or `"domain"` (domain-level data from collection sources, e.g. `rdap`) |
| target_id   | INTEGER NOT NULL | id into `ip_addresses`, `hostnames` or `domains`, per `target_type` |
| data        | TEXT NOT NULL | JSON blob, source-defined shape |
| fetched_at  | TEXT NOT NULL | |

A host can have multiple `results` rows from different sources (or the same
source across repeated scans) - `fetched_at` lets you tell which data is
current.

### `candidate_domains`
Out-of-scope registrable domains that a scan's enrichment sources related to
its targets (reverse-IP neighbours, PTR names). Recorded for review, never
scanned automatically. TLD siblings of the target (`brand.net` for
`brand.com`) are in scope instead: scanned as their own domain, not recorded
here (see README "Related hostnames and candidate domains").

| column     | type | notes |
|------------|------|-------|
| id         | INTEGER PK | |
| domain_id  | INTEGER NOT NULL REFERENCES domains(id) | the scanned domain that surfaced it |
| name       | TEXT NOT NULL | registrable domain, e.g. `brand.co.uk` |
| source     | TEXT NOT NULL | first source that reported it |
| via        | TEXT NOT NULL | the target it was related to (IP or hostname) |
| first_seen | TEXT NOT NULL | |
| last_seen  | TEXT NOT NULL | |

Unique on `(domain_id, name)`. Kept across re-scans (not pruned).

### `cloud_assets`
Cloud storage buckets (S3/GCS/Azure) a scan found for a domain, from
`bucketsearch`. `exposure` is `public` (lists contents anonymously) or
`private` (exists, denies anonymous access); non-existent buckets aren't
stored. Contents are never read.

| column     | type | notes |
|------------|------|-------|
| id         | INTEGER PK | |
| domain_id  | INTEGER NOT NULL REFERENCES domains(id) | |
| provider   | TEXT NOT NULL | `s3`, `gcs` or `azure` |
| name       | TEXT NOT NULL | bucket name |
| url        | TEXT NOT NULL | browseable base URL |
| exposure   | TEXT NOT NULL | `public` or `private` |
| source     | TEXT NOT NULL | |
| first_seen | TEXT NOT NULL | |
| last_seen  | TEXT NOT NULL | |

Unique on `(domain_id, provider, name)`. Kept across re-scans.

### `tool_outputs`
The raw report each external tool (nikto, wpscan, takeover, nuclei, trivy,
checkov, prowler, scoutsuite, theHarvester, gitleaks, trufflehog) wrote for a
target, so tools' report files never stay on disk. Parsed findings still go
to `results`; this is the tool's own output, for reference and download.

| column     | type | notes |
|------------|------|-------|
| id         | INTEGER PK | |
| domain_id  | INTEGER NOT NULL REFERENCES domains(id) | |
| tool       | TEXT NOT NULL | |
| target     | TEXT NOT NULL | what the tool ran against: URL, IP, repo URL, image ref, cloud provider, domain, or `repo:path@commit` for the secret scanners |
| content    | BLOB NOT NULL | the report, lzma-compressed (xz, preset 9e) |
| raw_size   | INTEGER NOT NULL | uncompressed size in bytes |
| created_at | TEXT NOT NULL | |

Unique on `(domain_id, tool, target)`: a re-scan replaces the report, and a
run that finds nothing deletes it. Deleted with the domain.

### `settings`
Key/value app settings edited on the web UI's Settings page (see
`settings.py`). Unset keys have no row.

| column | type | notes |
|--------|------|-------|
| key    | TEXT PK | e.g. `proxy_url`, `proxy_dns_server` |
| value  | TEXT NOT NULL | |

### `scan_jobs`
The web UI's scan jobs (see `web/scans.py`), so they outlive the process: a
job still `pending`/`running`/`cancelling` when the server starts was cut off
and is set to `interrupted`.

| column      | type | notes |
|-------------|------|-------|
| id          | TEXT PK | |
| domain      | TEXT NOT NULL | the domain the scan was started for |
| options     | TEXT NOT NULL | JSON of the job's `ScanOptions` (stages, sources) |
| status      | TEXT NOT NULL | `pending`, `running`, `cancelling`, `cancelled`, `completed`, `failed`, `interrupted` |
| stage       | TEXT NOT NULL | last stage reported |
| detail      | TEXT NOT NULL | |
| error       | TEXT | for `failed` |
| created_at  | TEXT NOT NULL | |
| started_at  | TEXT | first start, kept across resumes - source calls since then aren't repeated |
| finished_at | TEXT | |
| resumes     | INTEGER NOT NULL | how often the job was resumed |

### `scan_checkpoints`
What a scan job already finished (see `orchestrator.Checkpoints`), so
resuming it skips that work. Written only after the step's data is stored.
Dropped when the job completes, and per domain when the domain is deleted.

| column  | type | notes |
|---------|------|-------|
| job_id  | TEXT NOT NULL | |
| domain  | TEXT NOT NULL | |
| step    | TEXT NOT NULL | `stage:<name>`, a per-target run like `nuclei:<ip>` / `fingerprint:<ip>:<port>/<proto>` / `repo:<url>`, `queued` (a TLD sibling the job picked up) or `done` (domain finished) |
| done_at | TEXT NOT NULL | |

Primary key `(job_id, domain, step)`.

### `code_exposures`
Public GitHub code the `github` source found naming a domain's hostnames/IPs,
and secrets detected in those files. `kind` is `reference` (the target is
named in the file) or `secret` (a credential matched a rule). Secret values
are stored **in full**. Attached to the domain; `target` names the hostname/IP
(for a secret, the one whose search surfaced the file).

| column     | type | notes |
|------------|------|-------|
| id         | INTEGER PK | |
| domain_id  | INTEGER NOT NULL REFERENCES domains(id) | |
| kind       | TEXT NOT NULL | `reference` or `secret` |
| target     | TEXT NOT NULL | hostname/IP named |
| repo       | TEXT NOT NULL | `owner/name` |
| path       | TEXT NOT NULL | file path in the repo |
| commit_sha | TEXT NOT NULL | commit the permalink is pinned to |
| url        | TEXT NOT NULL | GitHub blob permalink (with line anchor when known) |
| line       | INTEGER | 1-based line, when known |
| snippet    | TEXT | the line naming the target (references) |
| rule       | TEXT | which secret rule matched (secrets) |
| secret     | TEXT | the full secret value (secrets) |
| first_seen | TEXT NOT NULL | |
| last_seen  | TEXT NOT NULL | |

Unique on `(domain_id, repo, path, target, kind, rule, secret)` - the
`commit_sha`/`line`/`url` are refreshed on re-sighting (a file edit doesn't
create a new row), so `last_seen` tracks whether an exposure is still present.

### `source_calls`
Usage ledger: one row per call a source makes (a `discover` for a domain, an
`enrich` for an IP/hostname), written by `governor.py`. Backs quota budgets
(count calls in a rolling window) and TTL skipping (last successful call for
a target), so both hold across runs.

| column      | type | notes |
|-------------|------|-------|
| id          | INTEGER PK | |
| source      | TEXT NOT NULL | |
| target_type | TEXT NOT NULL | `"domain"` (discovery), `"collect"` (collection), `"hostname"` or `"ip"` |
| target      | TEXT NOT NULL | the domain/hostname/address itself (not an id - survives pruning) |
| called_at   | TEXT NOT NULL | |
| ok          | INTEGER | NULL while in flight, then 1 if the call succeeded (the target is fresh for TTL purposes), else 0: it raised, it was an extra request (a further page) within a call, or its IP target was since pruned. Every row counts toward budgets. Calls a source declined as unavailable (missing key/binary) are deleted - nothing was sent |

## Why some sources key by IP and some by hostname

Most enrichment (Shodan, Qualys VMDR, DNS PTR lookups) is naturally
IP-keyed. Qualys SSL Labs is the exception: it grades a TLS handshake made
via SNI to a specific hostname, so the same IP can grade differently
depending on which hostname is tested. Each `Source` declares
`enrich_target_kind` (`"ip"` or `"hostname"`) and the orchestrator calls it
against the right identifier - see `sources/base.py` and
`orchestrator.py::_run_enrichment`.

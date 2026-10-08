# Test fixtures

Response bodies per source, under `<source>/`. Parsers are tested against
these rather than hand-written snippets, so the tests check what the service
actually sends.

- **Captured** fixtures were fetched from the real endpoint (date and URL in
  the file header where the format allows one, otherwise listed below) and
  trimmed/sanitized - no API keys, no data about anyone's real targets beyond
  public example domains.
- **Documented-shape** fixtures are for keyed APIs we had no key to capture
  from; they follow the provider's API docs. Replace them with a captured
  response when you have a key - the `pytest -m live` canaries
  (`tests/test_live_sources.py`) will tell you if the real shape differs.

| source | file | kind |
|--------|------|------|
| wayback | iana.org.json | captured 2026-09-26, `cdx/search/cdx?url=iana.org&matchType=domain&output=json&fl=original&collapse=urlkey&limit=10` |
| commoncrawl | collinfo.json, iana.org.jsonl | captured 2026-09-26 (collinfo trimmed to 2 indexes) |
| hackertarget | example.com.txt | captured 2026-09-26, `hostsearch/?q=example.com` |
| rapiddns | example.com.html, empty.html | captured 2026-09-26, trimmed to the results table |
| otx | iana.org.json | documented shape (anonymous access now 429s) |
| virustotal | subdomains_page1.json, subdomains_page2.json | documented shape |
| securitytrails | example.com.json | documented shape |
| fullhunt | example.com.json | documented shape |
| netlas | iana.org.json | captured 2026-09-26 keyless, `api/domains/?q=domain:*.iana.org`, trimmed to 6 items |
| fullhunt_web | iana.org.html, empty.html | captured 2026-09-26, `search?query=...`, trimmed to headings |
| greynoise | observed.json, not_observed.json | captured 2026-09-26 keyless, `v3/community/<ip>` (not_observed comes with HTTP 404) |
| ipinfo | 8.8.8.8.json, 192.0.43.8.json | captured 2026-09-26 keyless |
| hackertarget | reverse_192.0.43.8.txt | captured 2026-09-26, `reverseiplookup/?q=192.0.43.8` |
| urlscan | domain_iana.org.json, ip_192.0.43.8.json | captured 2026-09-26 keyless search, trimmed to 3/5 results |
| abuseipdb | check.json | documented shape |
| virustotal | ip_resolutions.json | documented shape |
| otx | ipv4_passive_dns.json | documented shape |
| rdap | iana.org.json | captured 2026-09-26, `rdap.org/domain/iana.org` (redirects to the registry's RDAP server) |

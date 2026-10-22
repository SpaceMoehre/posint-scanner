"""Collection source: email-authentication posture from DNS - whether the
domain can be spoofed in mail. Keyless, purely passive (a handful of DNS
queries the domain itself publishes).

Grades the three records that decide whether someone can forge mail *from*
the domain, plus CAA (which CAs may issue certs for it):

  - SPF (apex TXT `v=spf1`): the `all` qualifier (`-all` hard-fail vs the
    permissive `~all`/`?all`/`+all`), the >10-DNS-lookup limit that makes an
    SPF record a permerror (silently ignored by receivers), and the RFC
    violation of publishing more than one SPF record.
  - DMARC (`_dmarc.<domain>` TXT): the policy (`p=none` is monitor-only and
    does not stop spoofing; `quarantine`/`reject` enforce), partial `pct`,
    a missing `rua` (no visibility), and a weaker `sp` for subdomains.
  - DKIM: whether any *common* selector publishes a key. Advisory only -
    selectors are arbitrary, so a domain can sign mail with a selector not on
    the probe list; absence here is "none of the usual ones", not proof.
  - CAA: absent means any CA may issue a certificate for the domain.

The headline is `spoofable`: direct From-domain spoofing is stopped by DMARC
enforcement (`p=quarantine`/`reject`), not by SPF alone (SPF binds the
envelope sender, not the header From that users see), so a domain is spoofable
when DMARC is missing or `p=none` - regardless of how strict its SPF is.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from posint_scanner.dns_resolve import query_record_type
from posint_scanner.models import EnrichmentResult
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source

# Common DKIM selectors published by the major mail/ESP providers. Probing is
# cheap (one DNS query each) and keyless; this is deliberately a short, common
# list - selectors are arbitrary, so this can only ever confirm presence.
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "s1", "s2",
    "k1", "k2", "dkim", "mail", "smtp", "mandrill", "mxvault",
    "zoho", "fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3",
)

# SPF mechanisms that each cost a DNS lookup (RFC 7208 §4.6.4 caps the total
# at 10; exceeding it is a permerror and the whole SPF record is ignored).
_SPF_LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr:", "exists:", "redirect=")
# Bare `a` / `mx` (no `:domain`) also cost a lookup each.
_SPF_BARE_LOOKUP = re.compile(r"(?:^|\s)[?~+-]?(a|mx|ptr)(?=\s|$)", re.IGNORECASE)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding(id: str, severity: str, title: str, detail: str) -> dict:
    return {"id": id, "severity": severity, "title": title, "detail": detail}


def find_ids(findings: list[dict]) -> set[str]:
    return {f["id"] for f in findings}


def clean_txt_records(raw: list[str]) -> list[str]:
    """Normalize raw TXT answers from the resolver: a TXT record longer than
    255 bytes is published as several quoted chunks (`"abc" "def"`), which
    concatenate; dnspython renders each answer with its surrounding quotes."""
    cleaned = []
    for record in raw:
        # Join the quoted chunks ("a" "b" -> ab), then drop the outer quotes.
        cleaned.append(record.replace('" "', "").strip('"'))
    return cleaned


def _spf_records(txt: list[str]) -> list[str]:
    return [r for r in txt if r.lower().startswith("v=spf1")]


def _all_qualifier(record: str) -> str | None:
    """The qualifier on the terminal `all` mechanism, normalized (`all` with
    no qualifier is an implicit pass, i.e. `+all`)."""
    match = re.search(r"(?:^|\s)([?~+-]?)all(?=\s|$)", record, re.IGNORECASE)
    if match is None:
        return None
    return f"{match.group(1) or '+'}all"


def _spf_lookup_count(record: str) -> int:
    """DNS-lookup mechanisms in *this* record only. Nested `include`/`redirect`
    targets each expand into further lookups that count toward the RFC-7208
    limit of 10 but aren't resolved here (that needs recursive DNS), so this is
    a lower bound: `spf_too_many_lookups` catches records already over the cap
    at the top level, not every one that exceeds it once expanded."""
    lowered = record.lower()
    count = sum(lowered.count(mech) for mech in _SPF_LOOKUP_MECHANISMS)
    count += len(_SPF_BARE_LOOKUP.findall(record))
    return count


def grade_spf(txt: list[str], mx_present: bool) -> dict:
    records = _spf_records(txt)
    findings: list[dict] = []
    if not records:
        findings.append(_finding(
            "spf_missing", "high" if mx_present else "medium",
            "No SPF record",
            "Nothing declares which servers may send mail for this domain.",
        ))
        return {"found": False, "record": None, "all_qualifier": None,
                "lookup_count": 0, "findings": findings}

    if len(records) > 1:
        findings.append(_finding(
            "spf_multiple_records", "high", "Multiple SPF records",
            "More than one SPF record is a permerror (RFC 7208); receivers "
            "ignore SPF entirely.",
        ))
    record = records[0]
    qualifier = _all_qualifier(record)
    lookups = _spf_lookup_count(record)

    if qualifier == "+all":
        findings.append(_finding(
            "spf_pass_all", "critical", "SPF authorizes all senders (+all)",
            "`+all` lets any server pass SPF for this domain - worse than no SPF.",
        ))
    elif qualifier == "?all":
        findings.append(_finding(
            "spf_neutral", "medium", "SPF is neutral (?all)",
            "`?all` makes a neutral result - receivers treat it as no policy.",
        ))
    elif qualifier == "~all":
        findings.append(_finding(
            "spf_softfail", "low", "SPF soft-fails (~all)",
            "`~all` only soft-fails unauthorized senders; `-all` is the hard fail.",
        ))

    if lookups > 10:
        findings.append(_finding(
            "spf_too_many_lookups", "high", f"SPF needs {lookups} DNS lookups",
            "Over 10 DNS lookups is a permerror (RFC 7208); the SPF record is "
            "ignored by receivers.",
        ))

    return {"found": True, "record": record, "all_qualifier": qualifier,
            "lookup_count": lookups, "findings": findings}


def _dmarc_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def grade_dmarc(txt: list[str]) -> dict:
    records = [r for r in txt if r.lower().startswith("v=dmarc1")]
    findings: list[dict] = []
    if not records:
        findings.append(_finding(
            "dmarc_missing", "high", "No DMARC record",
            "Without DMARC, receivers have no instruction to reject forged mail "
            "claiming to be from this domain.",
        ))
        return {"found": False, "record": None, "policy": None,
                "subdomain_policy": None, "pct": None, "rua": None, "findings": findings}

    if len(records) > 1:
        findings.append(_finding(
            "dmarc_multiple_records", "medium", "Multiple DMARC records",
            "More than one DMARC record at `_dmarc` is invalid; receivers ignore all.",
        ))
    tags = _dmarc_tags(records[0])
    policy = (tags.get("p") or "").lower() or None
    sp = (tags.get("sp") or "").lower() or None
    rua = tags.get("rua")
    try:
        pct = int(tags["pct"]) if "pct" in tags else None
    except ValueError:
        pct = None

    if policy is None:
        findings.append(_finding(
            "dmarc_no_policy", "high", "DMARC record has no policy (p=)",
            "A DMARC record without the required `p=` tag is invalid and gives "
            "receivers no instruction - equivalent to no DMARC.",
        ))
    elif policy == "none":
        findings.append(_finding(
            "dmarc_policy_none", "medium", "DMARC policy is p=none",
            "`p=none` only monitors - it does not tell receivers to reject or "
            "quarantine spoofed mail.",
        ))
    if sp == "none" and policy in ("quarantine", "reject"):
        findings.append(_finding(
            "dmarc_subdomain_none", "medium", "DMARC subdomain policy is sp=none",
            "Subdomains are unprotected (`sp=none`) despite an enforcing policy "
            "on the apex - any subdomain is spoofable.",
        ))
    if pct is not None and pct < 100:
        findings.append(_finding(
            "dmarc_partial_pct", "low", f"DMARC applies to only {pct}% of mail",
            "`pct<100` leaves the rest of the mail stream unprotected.",
        ))
    if not rua:
        findings.append(_finding(
            "dmarc_no_reporting", "low", "No DMARC aggregate reporting (rua)",
            "Without `rua`, you get no visibility into who is sending as the domain.",
        ))

    return {"found": True, "record": records[0], "policy": policy,
            "subdomain_policy": sp, "pct": pct, "rua": rua, "findings": findings}


def grade_caa(caa_records: list[str]) -> dict:
    # `collect` targets the registrable (apex) domain, which is the top of the
    # org's own DNS tree, so an absent CAA here really does mean no issuance
    # restriction (RFC 8659 parent-walking would only reach the TLD, which
    # effectively never publishes CAA).
    findings: list[dict] = []
    records = [r for r in caa_records if r.strip()]
    if not records:
        findings.append(_finding(
            "caa_missing", "low", "No CAA record",
            "Without CAA, any certificate authority may issue a certificate for "
            "this domain.",
        ))
    return {"found": bool(records), "records": records, "findings": findings}


def dkim_selectors_present(probed: dict[str, list[str]]) -> list[str]:
    """Which probed selectors actually publish a DKIM key."""
    present = []
    for selector, records in probed.items():
        if any("v=dkim1" in r.lower() or "k=" in r.lower() or "p=" in r.lower()
               for r in records):
            present.append(selector)
    return present


def assess(
    spf_txt: list[str],
    dmarc_txt: list[str],
    caa_records: list[str],
    dkim_probed: dict[str, list[str]],
    mx_present: bool,
) -> dict:
    spf = grade_spf(spf_txt, mx_present)
    dmarc = grade_dmarc(dmarc_txt)
    caa = grade_caa(caa_records)
    dkim_present = dkim_selectors_present(dkim_probed)

    findings = [*spf["findings"], *dmarc["findings"], *caa["findings"]]
    if not dkim_present:
        findings.append(_finding(
            "dkim_no_common_selector", "info", "No DKIM key on common selectors",
            "None of the common DKIM selectors publish a key (selectors are "
            "arbitrary - the domain may still sign with a custom one).",
        ))

    # Direct From-domain spoofing is stopped by DMARC enforcement, not SPF.
    spoofable = dmarc["policy"] in (None, "none")

    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 9))
    return {
        "spoofable": spoofable,
        "mx_present": mx_present,
        "spf": spf,
        "dmarc": dmarc,
        "caa": caa,
        "dkim": {"selectors_present": dkim_present},
        "findings": findings,
    }


class EmailAuthSource(Source):
    name = "email_auth"
    ttl_days = DEFAULT_TTL_DAYS

    def collect(self, domain: str) -> EnrichmentResult:
        txt = clean_txt_records(query_record_type(domain, "TXT"))
        dmarc_txt = clean_txt_records(query_record_type(f"_dmarc.{domain}", "TXT"))
        caa = query_record_type(domain, "CAA")
        mx_present = bool(query_record_type(domain, "MX"))
        # One blocking DNS query per selector; fan them out so a slow/timing-out
        # resolver doesn't serialize all of them (they're independent lookups).
        def probe(selector: str) -> tuple[str, list[str]]:
            return selector, clean_txt_records(
                query_record_type(f"{selector}._domainkey.{domain}", "TXT")
            )

        with ThreadPoolExecutor(max_workers=len(DKIM_SELECTORS)) as executor:
            dkim_probed = dict(executor.map(probe, DKIM_SELECTORS))
        data = assess(
            spf_txt=txt,
            dmarc_txt=dmarc_txt,
            caa_records=caa,
            dkim_probed=dkim_probed,
            mx_present=mx_present,
        )
        return EnrichmentResult(
            source=self.name, target_type="domain", target=domain, data=data
        )

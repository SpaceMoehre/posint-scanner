"""Collection source: registered look-alike / typosquat domains of the
target, the same recon dnstwist does. Keyless, purely passive - it generates
name permutations of the target and resolves each against public resolvers;
it never touches the target's own infrastructure.

A permutation that resolves (A/AAAA) or has an MX record is treated as
*registered* and reported as a possible impersonation / phishing domain.
These are deliberately kept only in the domain's `data` - they are NOT fed
back as related hostnames or candidate domains: they belong to someone else
(often the very attacker you're watching for), so the scanner must never
resolve-and-enrich them as though they were the target's own.

Permutation families (a subset of dnstwist's): character omission,
repetition, adjacent transposition, keyboard-adjacent replacement/insertion,
homoglyph substitution, vowel swap, hyphen insertion, a trailing letter, and
public-suffix swaps against a common TLD list.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

import tldextract

from posint_scanner.dns_resolve import query_record_type, resolve_hostname
from posint_scanner.models import EnrichmentResult
from posint_scanner.sources.base import DEFAULT_TTL_DAYS, Source

logger = logging.getLogger(__name__)

# Bundled PSL snapshot, no runtime fetch - matches scope.py's extractor.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)

# Hard cap on generated permutations so a long label can't explode the DNS
# work (and a scan's runtime) without bound.
MAX_PERMUTATIONS = 600
# Concurrency for the resolution sweep. Bounded and modest: these are cheap
# public-resolver lookups, but a scan runs several of these pools at once.
DEFAULT_WORKERS = 20

_KEYBOARD = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "rygf", "y": "tugh",
    "u": "yijh", "i": "uojk", "o": "ipkl", "p": "ol", "a": "qwsz", "s": "awedxz",
    "d": "serfcx", "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "j": "huikmn",
    "k": "jiolm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
    "1": "2q", "2": "13qw", "3": "24we", "4": "35er", "5": "46rt", "6": "57ty",
    "7": "68yu", "8": "79ui", "9": "80io", "0": "9op",
}
_HOMOGLYPHS = {
    "o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"],
    "e": ["3"], "3": ["e"], "a": ["4"], "4": ["a"], "s": ["5"], "5": ["s"],
    "b": ["8"], "8": ["b"], "g": ["9", "q"], "t": ["7"], "7": ["t"], "z": ["2"],
    "m": ["rn"], "w": ["vv"],
}
_VOWELS = "aeiou"
# TLDs a squatter most often registers the same label under.
_COMMON_TLDS = (
    "com", "net", "org", "info", "biz", "co", "io", "app", "online", "site",
    "xyz", "top", "live", "shop", "store", "cloud", "de", "co.uk", "eu",
)


def _label_variants(label: str) -> set[str]:
    """Typo/homoglyph variants of one domain label (no TLD involved)."""
    out: set[str] = set()
    n = len(label)

    for i in range(n):
        # omission
        out.add(label[:i] + label[i + 1 :])
        # repetition
        out.add(label[:i] + label[i] + label[i:])
        # homoglyph substitution
        for glyph in _HOMOGLYPHS.get(label[i], ()):
            out.add(label[:i] + glyph + label[i + 1 :])
        # keyboard-adjacent replacement + insertion
        for key in _KEYBOARD.get(label[i], ""):
            out.add(label[:i] + key + label[i + 1 :])
            out.add(label[:i] + key + label[i:])
        # vowel swap
        if label[i] in _VOWELS:
            for vowel in _VOWELS:
                if vowel != label[i]:
                    out.add(label[:i] + vowel + label[i + 1 :])

    for i in range(n - 1):
        # adjacent transposition
        out.add(label[:i] + label[i + 1] + label[i] + label[i + 2 :])
        # hyphen insertion
        out.add(label[:i + 1] + "-" + label[i + 1 :])

    # homoglyph substitution of *every* occurrence of a character at once
    # (g00gle, paypa1, etc.) - the most common real look-alike shape
    for src, glyphs in _HOMOGLYPHS.items():
        if src in label:
            for glyph in glyphs:
                out.add(label.replace(src, glyph))

    # a trailing extra letter (common "typo-adjacent" registration)
    for ch in "abcdefghijklmnopqrstuvwxyz":
        out.add(label + ch)

    # keep only labels that are still valid and actually different
    out.discard(label)
    return {
        v for v in out
        if v and not v.startswith("-") and not v.endswith("-") and "--" not in v
    }


def permutations(domain: str) -> list[str]:
    """Registered-or-not look-alike candidates for `domain`. Operates on the
    registrable label (subdomains dropped, public suffix preserved); also
    swaps the public suffix for common TLDs. Deterministically ordered and
    capped at MAX_PERMUTATIONS."""
    extracted = _EXTRACT(domain)
    label = extracted.domain
    suffix = extracted.suffix
    if not label or not suffix:
        return []

    seen: set[str] = set()
    ordered: list[str] = []

    def add(name: str) -> None:
        if name != domain and name not in seen:
            seen.add(name)
            ordered.append(name)

    # Same label under a swapped public suffix FIRST: there are only a handful
    # and they're high-value squats, so they must not be truncated away by a
    # long label's flood of typo variants (which the cap below would cut).
    for tld in _COMMON_TLDS:
        if tld != suffix:
            add(f"{label}.{tld}")
    # then the (potentially large) set of same-suffix typo/homoglyph variants
    for variant in sorted(_label_variants(label)):
        add(f"{variant}.{suffix}")

    return ordered[:MAX_PERMUTATIONS]


class LookalikeSource(Source):
    name = "lookalike"
    category = "passive"
    default_enabled = False  # opt-in: generates hundreds of DNS lookups
    ttl_days = DEFAULT_TTL_DAYS

    def __init__(self, workers: int = DEFAULT_WORKERS) -> None:
        self.workers = workers

    def _check(self, name: str) -> dict | None:
        """A registered look-alike, or None if the name resolves to nothing."""
        addresses = resolve_hostname(name)
        mx = query_record_type(name, "MX")
        if not addresses and not mx:
            return None
        return {"name": name, "addresses": addresses, "mx": mx}

    def collect(self, domain: str) -> EnrichmentResult:
        candidates = permutations(domain)
        registered: list[dict] = []
        with ThreadPoolExecutor(max_workers=max(1, self.workers)) as executor:
            for hit in executor.map(self._check, candidates):
                if hit is not None:
                    registered.append(hit)
        registered.sort(key=lambda r: r["name"])
        if registered:
            logger.info(
                "lookalike: %d registered look-alike domain(s) for %s",
                len(registered), domain,
            )
        return EnrichmentResult(
            source=self.name,
            target_type="domain",
            target=domain,
            data={"checked": len(candidates), "registered": registered},
            # Never fed back: these are third-party (often hostile) domains.
            related_hostnames=[],
        )

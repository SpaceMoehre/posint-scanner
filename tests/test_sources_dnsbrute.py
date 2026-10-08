import pytest

from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.dnsbrute import (
    DnsBruteSource,
    candidate_hostname,
    load_wordlist,
)


def wordlist(tmp_path, text):
    path = tmp_path / "words.txt"
    path.write_text(text)
    return str(path)


class TestLoadWordlist:
    def test_strips_comments_blanks_and_lowercases(self, tmp_path):
        path = wordlist(tmp_path, "# seclists header\nWWW\n\napi \n# c\nmail\nwww\n")
        assert load_wordlist(path) == ["www", "api", "mail"]

    def test_missing_file_raises_unavailable(self, tmp_path):
        with pytest.raises(SourceUnavailableError):
            load_wordlist(str(tmp_path / "nope.txt"))


class TestCandidate:
    def test_joins_label_and_domain(self):
        assert candidate_hostname("api", "example.com") == "api.example.com"


class TestDiscover:
    def _source(self, tmp_path, mapping, **kw):
        # mapping: hostname -> list of IPs it resolves to
        resolve = lambda host: mapping.get(host, [])  # noqa: E731
        return DnsBruteSource(
            wordlist=wordlist(tmp_path, "api\nwww\nmail\nvpn"),
            resolve=resolve,
            probe_labels=["zzprobe1", "zzprobe2"],
            **kw,
        )

    def test_returns_only_names_that_resolve(self, tmp_path):
        source = self._source(
            tmp_path, {"api.example.com": ["1.1.1.1"], "vpn.example.com": ["2.2.2.2"]}
        )
        found = source.discover("example.com")
        assert sorted(h.name for h in found) == ["api.example.com", "vpn.example.com"]
        assert all(h.source == "dnsbrute" for h in found)

    def test_filters_wildcard_answers(self, tmp_path):
        # the domain wildcards every unknown name to 9.9.9.9; a real host has
        # a different IP and is kept, a wildcard-only match is dropped
        mapping = {
            "zzprobe1.example.com": ["9.9.9.9"],
            "zzprobe2.example.com": ["9.9.9.9"],
            "api.example.com": ["9.9.9.9"],          # just the wildcard
            "vpn.example.com": ["9.9.9.9", "2.2.2.2"],  # real host behind wildcard
        }
        found = [h.name for h in self._source(tmp_path, mapping).discover("example.com")]
        assert found == ["vpn.example.com"]

    def test_no_wildcard_keeps_everything_that_resolves(self, tmp_path):
        mapping = {"api.example.com": ["1.1.1.1"]}  # probes resolve to nothing
        found = [h.name for h in self._source(tmp_path, mapping).discover("example.com")]
        assert found == ["api.example.com"]

    def test_max_words_caps_the_wordlist(self, tmp_path):
        seen = []
        resolve = lambda host: seen.append(host) or []  # noqa: E731
        DnsBruteSource(
            wordlist=wordlist(tmp_path, "api\nwww\nmail\nvpn"),
            resolve=resolve,
            probe_labels=[],
            max_words=2,
            workers=1,
        ).discover("example.com")
        # 2 candidates (probes disabled here); order-independent
        assert set(seen) == {"api.example.com", "www.example.com"}

    def test_missing_wordlist_raises(self, tmp_path):
        source = DnsBruteSource(wordlist=str(tmp_path / "missing.txt"), resolve=lambda h: [])
        with pytest.raises(SourceUnavailableError):
            source.discover("example.com")


class TestConfig:
    def test_registered_but_off_by_default(self):
        from posint_scanner.config import Config
        from posint_scanner.registry import SOURCE_CLASSES, build_sources

        assert any(c.name == "dnsbrute" for c in SOURCE_CLASSES)
        assert "dnsbrute" not in {s.name for s in build_sources(Config())}

    def test_enabled_via_config_with_wordlist(self, tmp_path):
        from posint_scanner.config import Config
        from posint_scanner.registry import build_sources

        path = wordlist(tmp_path, "api")
        cfg = Config(sources={"dnsbrute": {"enabled": True, "wordlist": path}})
        source = next(s for s in build_sources(cfg) if s.name == "dnsbrute")
        assert source.wordlist == path

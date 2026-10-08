from posint_scanner.sources.common import host_of, scoped_hostnames


class TestHostOf:
    def test_plain_hostname(self):
        assert host_of("API.Example.com.") == "api.example.com"

    def test_url_with_port_path_and_userinfo(self):
        assert host_of("https://user:pw@www.example.com:8443/a/b?c=d") == "www.example.com"

    def test_wildcard_is_stripped(self):
        assert host_of("*.dev.example.com") == "dev.example.com"

    def test_garbage_is_none(self):
        assert host_of("not a host") is None
        assert host_of("") is None


class TestScopedHostnames:
    def test_keeps_domain_and_subdomains_deduped(self):
        found = scoped_hostnames(
            "example.com",
            ["www.example.com", "WWW.example.com", "example.com", "http://a.example.com:80/"],
            "src",
        )
        assert [h.name for h in found] == ["www.example.com", "example.com", "a.example.com"]
        assert all(h.source == "src" for h in found)

    def test_drops_out_of_scope_and_lookalikes(self):
        found = scoped_hostnames(
            "example.com", ["evil-example.com", "example.com.evil.net", "other.org"], "src"
        )
        assert found == []

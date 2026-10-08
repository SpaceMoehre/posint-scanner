"""The project makes every outbound request with TLS verification off, so a
target's broken/self-signed cert can't abort recon. Lock that in."""

from unittest.mock import MagicMock, patch

from posint_scanner.retry import VERIFY_TLS
from posint_scanner.sources.common import http_get


def test_policy_constant_is_off():
    assert VERIFY_TLS is False


def test_http_get_passes_verify_false():
    fake = MagicMock(status_code=200)
    with patch("posint_scanner.sources.common.requests.get", return_value=fake) as get:
        http_get("src", "https://example.com/")
    assert get.call_args.kwargs["verify"] is False


def test_every_direct_requests_call_threads_verify_through():
    # guard against a new call site (or a refactor) quietly re-enabling
    # verification: every requests.get/post in the package passes verify=.
    import ast
    import pathlib

    root = pathlib.Path("src/posint_scanner")
    offenders = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr in {"get", "post", "request"}
                    and isinstance(func.value, ast.Name) and func.value.id == "requests"):
                if not any(kw.arg == "verify" for kw in node.keywords):
                    offenders.append(f"{path}:{node.lineno}")
    assert offenders == [], f"requests call(s) without verify=: {offenders}"


def test_http_get_follows_redirects():
    from unittest.mock import MagicMock, patch
    from posint_scanner.sources.common import http_get
    fake = MagicMock(status_code=200)
    with patch("posint_scanner.sources.common.requests.get", return_value=fake) as get:
        http_get("src", "https://example.com/")
    assert get.call_args.kwargs["allow_redirects"] is True

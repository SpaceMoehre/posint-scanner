from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_tool_dirs(tmp_path, monkeypatch):
    """Tool sandboxes, slot files and caches under the test's own tmp dir.
    Sandboxes are plain dirs there (no bwrap - see toolrun._test_root)."""
    from posint_scanner import toolrun

    monkeypatch.setattr(toolrun, "_test_root", tmp_path / ".sandboxes")
    monkeypatch.setattr(toolrun, "_slots_dir", tmp_path / ".posint-slots")
    monkeypatch.setattr(toolrun, "_cache_root", tmp_path / ".posint-cache")
    monkeypatch.setattr(toolrun, "_limits", toolrun._limits)
    return tmp_path


@pytest.fixture(autouse=True)
def no_live_port_verify():
    """The port verification stage runs by default and TCP-connects every
    reported port - autouse-mock it to "open" everywhere, so scans keep the
    services their fake sources report. Tests of the stage override this."""
    from unittest.mock import patch

    with patch("posint_scanner.orchestrator.tcp_connect", return_value=True) as mock_connect:
        yield mock_connect


@pytest.fixture
def wpscan_db():
    """wpscan's vulnerability DB as `update-dbs` leaves it in the cache dir."""
    from posint_scanner import toolrun

    path = toolrun.cache_dir("wpscan") / ".wpscan" / "db"
    path.mkdir(parents=True)
    return path


def load_fixture(source: str, name: str) -> str:
    """A response body captured from the real service (sanitized), stored at
    tests/fixtures/<source>/<name>. See tests/fixtures/README.md."""
    return (FIXTURES / source / name).read_text()


def pytest_collection_modifyitems(config, items):
    # Live canary tests hit real endpoints: only run when selected with -m live.
    if "live" in (config.getoption("-m") or ""):
        return
    skip = pytest.mark.skip(reason="live endpoint test - run with: pytest -m live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)

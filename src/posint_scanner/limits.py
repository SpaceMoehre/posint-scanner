"""Process resource limits.

A scan holds hundreds of sockets at once (netblock sweep, port scan), and the
web UI can run several scans side by side. Containers often start processes
with a soft RLIMIT_NOFILE of 1024 - well under what that needs, and hitting it
fails everything at once (EMFILE: no sockets, and SQLite can't open files).
The hard limit is usually far higher, and raising soft to hard needs no
privileges.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def raise_open_files_limit() -> int | None:
    """Raise the soft open-files limit to the hard limit. Returns the soft
    limit now in effect, or None where the platform has no such limit."""
    try:
        import resource
    except ImportError:  # Windows
        return None
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != hard:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
            soft = hard
        except (ValueError, OSError) as exc:  # e.g. macOS with an unlimited hard limit
            logger.warning("could not raise open-files limit from %s: %s", soft, exc)
    logger.info("open-files limit: %s", soft)
    return soft

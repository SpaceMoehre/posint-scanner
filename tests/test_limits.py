import resource

from posint_scanner.limits import raise_open_files_limit


def test_raises_soft_limit_to_hard():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(256, hard), hard))
        assert raise_open_files_limit() == hard
        assert resource.getrlimit(resource.RLIMIT_NOFILE) == (hard, hard)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

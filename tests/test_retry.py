from unittest.mock import Mock

import pytest
import requests

from posint_scanner.retry import AuthError, raise_for_auth_error, with_retry


class TestWithRetry:
    def test_retries_on_connection_error_then_succeeds(self):
        calls = Mock(side_effect=[requests.ConnectionError("boom"), "ok"])

        @with_retry
        def flaky():
            return calls()

        assert flaky() == "ok"
        assert calls.call_count == 2

    def test_gives_up_after_three_attempts_on_persistent_5xx(self):
        response = Mock(status_code=503)
        error = requests.HTTPError(response=response)
        calls = Mock(side_effect=error)

        @with_retry
        def always_fails():
            return calls()

        with pytest.raises(requests.HTTPError):
            always_fails()
        assert calls.call_count == 3

    def test_does_not_retry_auth_error(self):
        calls = Mock(side_effect=AuthError("bad key"))

        @with_retry
        def unauthorized():
            return calls()

        with pytest.raises(AuthError):
            unauthorized()
        assert calls.call_count == 1

    def test_does_not_retry_client_error_404(self):
        response = Mock(status_code=404)
        error = requests.HTTPError(response=response)
        calls = Mock(side_effect=error)

        @with_retry
        def not_found():
            return calls()

        with pytest.raises(requests.HTTPError):
            not_found()
        assert calls.call_count == 1

    def test_retries_on_429(self):
        response = Mock(status_code=429)
        error = requests.HTTPError(response=response)
        calls = Mock(side_effect=[error, "ok"])

        @with_retry
        def rate_limited():
            return calls()

        assert rate_limited() == "ok"
        assert calls.call_count == 2


class TestRaiseForAuthError:
    def test_raises_auth_error_on_401(self):
        response = Mock(status_code=401)
        with pytest.raises(AuthError, match="bad key"):
            raise_for_auth_error(response, "bad key")

    def test_does_nothing_on_200(self):
        response = Mock(status_code=200)
        raise_for_auth_error(response, "should not raise")

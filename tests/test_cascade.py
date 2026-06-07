from altissimo.auth.cascade import AuthCascade


class MockAuth:
    def __init__(self, result=None):
        self.result = result
        self.called = False

    def __call__(self, request):
        self.called = True
        return self.result


def test_cascade_returns_first_success():
    """Test that AuthCascade returns the first non-None result and stops."""
    auth1 = MockAuth(result=None)
    auth2 = MockAuth(result="user2")
    auth3 = MockAuth(result="user3")

    cascade = AuthCascade([auth1, auth2, auth3])
    result = cascade("dummy_request")

    assert result == "user2"
    assert auth1.called is True
    assert auth2.called is True
    assert auth3.called is False  # Should short-circuit


def test_cascade_returns_none_if_all_fail():
    """Test that AuthCascade returns None if no method succeeds."""
    auth1 = MockAuth(result=None)
    auth2 = MockAuth(result=None)

    cascade = AuthCascade([auth1, auth2])
    result = cascade("dummy_request")

    assert result is None
    assert auth1.called is True
    assert auth2.called is True

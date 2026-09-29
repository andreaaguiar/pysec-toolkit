import threading

from pysec import ssh_brute_force


def test_attempt_login_success(monkeypatch):
    monkeypatch.setattr(ssh_brute_force, "ssh_connect", lambda *a, **k: 0)
    result, response, password = ssh_brute_force.attempt_login("h", 22, "user", "pw", False, 5)
    assert response == 0
    assert password == "pw"
    assert "SUCCESS" in result


def test_attempt_login_failure_is_silent_without_verbose(monkeypatch):
    monkeypatch.setattr(ssh_brute_force, "ssh_connect", lambda *a, **k: 1)
    result, response, _ = ssh_brute_force.attempt_login("h", 22, "user", "pw", False, 5)
    assert response == 1
    assert result is None


def test_attempt_login_skips_when_stopped(monkeypatch):
    calls = []
    monkeypatch.setattr(ssh_brute_force, "ssh_connect", lambda *a, **k: calls.append(1))
    stop_event = threading.Event()
    stop_event.set()
    result, response, password = ssh_brute_force.attempt_login(
        "h", 22, "user", "pw", False, 5, 0, stop_event
    )
    assert response == -1
    assert password == "pw"
    assert calls == []

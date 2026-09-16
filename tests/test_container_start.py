import subprocess
from types import SimpleNamespace

import container_start


def test_diagnostic_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AUTH_DIAGNOSTIC_ON_STARTUP", raising=False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("Unexpected process")))
    container_start.run_auth_diagnostic()


def test_enabled_diagnostic_is_bounded_and_does_not_forward_stderr(monkeypatch, capsys):
    monkeypatch.setenv("AUTH_DIAGNOSTIC_ON_STARTUP", "1")

    def run(args, **kwargs):
        assert args == [container_start.sys.executable, "diagnose_existing_auth.py"]
        assert kwargs["timeout"] == 20
        assert kwargs["capture_output"] is True
        return SimpleNamespace(returncode=0, stdout='{"stage":"complete","owner_match":false}', stderr="private sentinel")

    monkeypatch.setattr(subprocess, "run", run)
    container_start.run_auth_diagnostic()
    output = capsys.readouterr()
    assert '"owner_match": false' in output.out
    assert "private sentinel" not in output.out + output.err


def test_diagnostic_timeout_cannot_block_startup_or_leak_exception(monkeypatch, capsys):
    monkeypatch.setenv("AUTH_DIAGNOSTIC_ON_STARTUP", "1")

    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired("private sentinel", 20)

    monkeypatch.setattr(subprocess, "run", run)
    container_start.run_auth_diagnostic()
    output = capsys.readouterr()
    assert "diagnostic_unavailable" in output.out
    assert "private sentinel" not in output.out + output.err

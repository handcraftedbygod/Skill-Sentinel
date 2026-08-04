"""Unit tests for sentinel.cli's argument handling and _run_scan orchestration
(exit codes 0-5). Banner/mascot rendering has its own suite in test_banner.py.

Exit codes exercised here reuse real example fixtures where the static pass
alone determines the outcome (no Docker needed), and mock ensure_docker_available/
run_skill_in_sandbox for the two Docker-dependent failure paths.
"""

from pathlib import Path

import sentinel.cli as cli
from sentinel.cli import main
from sentinel.sandbox import DockerUnavailableError, SentinelError

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

MINIMAL_SKILL_MD = """---
name: test-skill
description: A minimal test skill.
---

Body text.
"""


def _write_skill(tmp_path: Path, script: str | None = None) -> Path:
    (tmp_path / "SKILL.md").write_text(MINIMAL_SKILL_MD, encoding="utf-8")
    if script is not None:
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "run.py").write_text(script, encoding="utf-8")
    return tmp_path


def test_bare_invocation_shows_welcome_and_exits_zero(capsys):
    exit_code = main([])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Get started" in out
    assert "skilltrace scan ./my-skill" in out


def test_semantic_review_without_api_key_returns_5(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _write_skill(tmp_path)
    exit_code = main(["scan", str(tmp_path), "--no-sandbox", "--semantic-review"])
    assert exit_code == 5
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_unresolvable_source_returns_2(tmp_path, capsys):
    exit_code = main(["scan", str(tmp_path / "does-not-exist")])
    assert exit_code == 2
    assert "error:" in capsys.readouterr().err


def test_no_skill_md_found_returns_2(tmp_path, capsys):
    exit_code = main(["scan", str(tmp_path)])
    assert exit_code == 2
    assert "SKILL.md" in capsys.readouterr().err


def test_docker_unavailable_returns_3(tmp_path, monkeypatch, capsys):
    _write_skill(tmp_path)
    monkeypatch.setattr(
        cli,
        "ensure_docker_available",
        lambda: (_ for _ in ()).throw(DockerUnavailableError("docker not found")),
    )
    exit_code = main(["scan", str(tmp_path)])
    assert exit_code == 3
    assert "docker not found" in capsys.readouterr().err


def test_sandbox_error_returns_4(tmp_path, monkeypatch, capsys):
    _write_skill(tmp_path, script="print('hi')\n")
    monkeypatch.setattr(cli, "ensure_docker_available", lambda: None)

    def _raise(*args, **kwargs):
        raise SentinelError("sandbox blew up")

    monkeypatch.setattr(cli, "run_skill_in_sandbox", _raise)
    exit_code = main(["scan", str(tmp_path)])
    assert exit_code == 4
    assert "sandbox blew up" in capsys.readouterr().err


def test_fail_threshold_triggers_exit_1():
    exit_code = main(
        [
            "scan",
            str(EXAMPLES_DIR / "malicious" / "pdf-formatter"),
            "--no-sandbox",
            "--fail-threshold",
            "high",
        ]
    )
    assert exit_code == 1


def test_clean_scan_returns_0():
    exit_code = main(["scan", str(EXAMPLES_DIR / "clean" / "word-counter"), "--no-sandbox"])
    assert exit_code == 0

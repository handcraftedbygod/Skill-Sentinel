"""Unit tests for sentinel.sandbox's pure log-parsing functions.

These run against static fixture logs and need no Docker — the orchestration
functions (build_sandbox_image, run_skill_in_sandbox) are exercised manually,
per SPEC.md's verification section, since they need a real Docker daemon.
"""

from pathlib import Path

from sentinel.sandbox import (
    parse_dnsmasq_log,
    parse_mitm_log,
    parse_strace_log,
    strace_connect_events,
    strace_execve_events,
    strace_notable_openat_events,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_strace_log_events():
    events = parse_strace_log(FIXTURES_DIR / "sample_strace.log")
    syscalls = [e.syscall for e in events]
    assert syscalls.count("connect") == 3
    assert syscalls.count("openat") == 3
    assert syscalls.count("execve") == 1


def test_parse_strace_log_stitches_unfinished_resumed():
    events = parse_strace_log(FIXTURES_DIR / "sample_strace.log")
    ssh_key_reads = [e for e in events if "id_rsa" in e.raw_args]
    assert len(ssh_key_reads) == 1
    assert "ENOENT" in ssh_key_reads[0].result


def test_strace_connect_events_filters_af_inet():
    events = parse_strace_log(FIXTURES_DIR / "sample_strace.log")
    connects = strace_connect_events(events)
    assert len(connects) == 2
    assert all("AF_INET" in e.raw_args for e in connects)


def test_strace_execve_events():
    events = parse_strace_log(FIXTURES_DIR / "sample_strace.log")
    execs = strace_execve_events(events)
    assert len(execs) == 1
    assert "python3" in execs[0].raw_args


def test_strace_notable_openat_events_excludes_allowlisted():
    events = parse_strace_log(FIXTURES_DIR / "sample_strace.log")
    notable = strace_notable_openat_events(events)
    notable_paths = [e.raw_args for e in notable]
    assert any("id_rsa" in p for p in notable_paths)
    assert not any("/usr/lib/python3.12" in p for p in notable_paths)


def test_parse_dnsmasq_log():
    queries = parse_dnsmasq_log(FIXTURES_DIR / "sample_dnsmasq.log")
    names = {q.name for q in queries}
    assert names == {"evil-collector.io"}
    a_query = next(q for q in queries if q.qtype == "A")
    assert a_query.answer == "127.0.0.1"


def test_parse_mitm_log():
    flows = parse_mitm_log(FIXTURES_DIR / "sample_mitm.log")
    assert len(flows) == 3

    request = flows[0]
    assert request.kind == "http_request"
    assert request.host == "evil-collector.io"
    assert request.method == "POST"
    assert request.path == "/exfil"

    response = flows[1]
    assert response.kind == "http_response"
    assert response.status_code == 502

    failed = flows[2]
    assert failed.kind == "tls_handshake_failed"
    assert failed.sni == "pinned-host.example"


def test_parse_missing_logs_return_empty():
    assert parse_strace_log(FIXTURES_DIR / "does-not-exist.log") == []
    assert parse_dnsmasq_log(FIXTURES_DIR / "does-not-exist.log") == []
    assert parse_mitm_log(FIXTURES_DIR / "does-not-exist.log") == []

> **Note:** this is the implementation plan as approved before coding started. One
> detail below was subsequently improved during implementation: the "locked-in
> deviation" section describes accepting a visibility gap for hardcoded-IP
> exfiltration attempts under `--network none`. In practice, a local-only
> `iptables` REDIRECT (self-contained inside the sandbox's own network
> namespace — no bridge network, no host NAT, still `--network none`) closes
> that gap too, so the shipped `docker/entrypoint.sh` captures the full
> decrypted request even for that attack pattern. See the README's "How it
> works" section for what was actually built.

# SkillTrace — Build v1 (SPEC.md steps 1-6)

## Context

This repo (`handcraftedbygod/SkillTrace`) currently contains only `LICENSE`, a 1-line `README.md`, and a fully-written `SPEC.md` design doc — no code yet. `SPEC.md` explains the motivation in detail: a July 2026 academic paper (arXiv:2607.02357) disclosed **SkillCloak**, malicious Claude Skills that hide payloads and evade the static-analysis-only scanners that currently exist for this ecosystem. Nobody has shipped a friendly, dynamic/behavioral scanner yet — that's the validated gap this project fills, timed to a fresh news hook.

This plan implements SPEC.md's build-order **steps 1-6**: a complete, installable `skilltrace` CLI that sandboxes a candidate skill in Docker, traces its actual behavior (`strace` for subprocess/network/file activity, `mitmproxy` for decrypted HTTPS bodies, `dnsmasq` as a DNS sinkhole), runs cheap static heuristics as a first pass, and produces a Markdown/JSON risk report. **Steps 7-8** (scanning real public repos for launch content, flipping the repo public) are explicitly out of scope for this session — those involve external, hard-to-reverse actions that need separate confirmation later.

**Environment caveat, confirmed this session:** the Docker CLI is present but no daemon is currently running here (`/var/run/docker.sock` missing; `dockerd`/`containerd` binaries exist but haven't been started). This session appears to be a Firecracker microVM (real kernel boot, not a shared-kernel container), so starting `dockerd` is plausible — but that's a state-changing action to attempt during implementation (outside plan mode), not something confirmed yet. Practical effect: **steps 1, 5, and the non-sandbox parts of 4 and 6 are buildable and fully verifiable in this session right now; steps 2, 3, and the sandbox-integration parts of 4 are buildable now but only manually verifiable once a Docker daemon is confirmed reachable** (either by starting one here, or falling back to GitHub Actions runners, which have Docker working by default — first guaranteed-Docker point in the whole pipeline). Implementation should attempt starting `dockerd` early and adjust verification expectations based on the result, rather than blocking on it.

**Locked-in deviation from SPEC's literal wording:** the sandbox container uses `--network none` with dnsmasq + mitmproxy bound to loopback *inside* the container, rather than a bridge network + iptables redirect. Simpler, needs only `--cap-add=SYS_PTRACE` (no `NET_ADMIN`/`NET_RAW`), and safety is structural (no route out exists at all) rather than DNS-lie-based. Tradeoff, accepted: a payload that connects straight to a hardcoded IP (skipping DNS) gets an immediate `ENETUNREACH` — `strace` still logs the attempted `connect()` + destination IP, but mitmproxy never sees that specific flow, so there's no decrypted body for that one attack pattern. Document this limitation in the README.

## Architecture (per SPEC.md, unchanged)

```
skilltrace/
  README.md
  pyproject.toml                   — pip/pipx-installable, entry point `skilltrace`
  sentinel/
    __init__.py
    findings.py                    — shared Finding dataclass + Severity enum (used by heuristics.py and report.py)
    skillmd.py                     — parse SKILL.md frontmatter, discover bundled scripts/resources, extract usage examples
    heuristics.py                  — static red flags: base64 blobs, eval/exec-of-decode, hidden dotfile executables
    allowlist.py                   — benign openat() path prefixes (/usr, /lib, site-packages, ...)
    sandbox.py                     — shells out to `docker` CLI; builds/runs sandbox image; strace + dnsmasq + mitm log parsing
    report.py                      — merges findings into Markdown/JSON report with risk score
    cli.py                         — argparse: scan <path|git-url> [--invoke CMD] [--allow-network] [--json] [--fail-threshold] [-o]
  docker/
    Dockerfile                     — python:3.12-slim + node + strace + ca-certificates + mitmproxy; bakes mitmproxy CA at build time
    dnsmasq.conf                   — loopback listener, wildcard → mitmproxy
    mitmproxy-addon.py             — logs decrypted host/path/body per request as JSON-lines
    entrypoint.sh                  — sequences dnsmasq → mitmproxy → strace-wrapped invocation
  .github/workflows/
    skill-ci.yml.example
  examples/
    benign-skill/                  — trivial real skill fixture, scans clean
    malicious-sample/               — synthetic SkillCloak-style fixture (self-decoding payload + hidden dotfile exec), clearly labeled as inert test fixture
  tests/
    test_heuristics.py             — required runnable check: malicious fixture flagged, benign clean
    fixtures/                      — static sample strace/dnsmasq/mitm logs for unit-testing parsers without Docker
```

## Build steps

### Step 0 — scaffolding
- `pyproject.toml` (deps: `pyyaml`; dev: `pytest`; entry point `skilltrace = "sentinel.cli:main"`), `sentinel/__init__.py`.

### Step 1 — `skillmd.py` + `heuristics.py` + `findings.py` (no Docker needed)
- `findings.py`: `Finding` dataclass, `Severity` enum — shared type both heuristics and the report use.
- `skillmd.py`: `parse_skill_md()` (YAML frontmatter + body), `discover_bundled_files()`, `extract_usage_examples()`. Raise a clear `SkillMdNotFoundError` (not a bare `FileNotFoundError`) when `SKILL.md` is missing; tolerate malformed/absent frontmatter.
- `heuristics.py`: `scan_file_for_base64_blobs()`, `scan_file_for_eval_exec_decode()` (AST-based for `.py`, regex fallback for JS), `scan_for_hidden_executable_content()`, orchestrator `run_heuristics()`.
- **Done when:** modules import and run cleanly against an ad hoc temp directory. Fully verifiable now.

### Step 2 — `docker/Dockerfile` + `dnsmasq.conf` + `mitmproxy-addon.py` + `entrypoint.sh`
- Dockerfile: `ARG`/`ENV` proxy plumbing early (build-time only, stripped before runtime) so `apt-get`/`pip install mitmproxy` succeed through this environment's proxy; pre-bake the mitmproxy CA at build time into the OS trust store *and* `certifi`'s bundle (`requests`/`urllib3` ignore the OS store).
- `entrypoint.sh`: start dnsmasq (loopback) → start `mitmdump` (loopback) → poll-wait both ready → `exec strace -f -tt -s 256 -e trace=execve,connect,openat -o /scratch/strace.log -- "$@"`.
- **Done when:** `docker build` succeeds; manual smoke test (`curl https://example.com` inside the container) shows the query in the dnsmasq log, the decrypted host+path in the mitm log, and the connect/execve calls in strace — **pending Docker daemon availability**.

### Step 3 — `sandbox.py`
- `ensure_docker_available()` — distinct errors for "CLI not on PATH" vs. "daemon unreachable", per SPEC's verification requirement.
- `build_sandbox_image()` — content-hash cached, passes proxy build-args.
- `resolve_skill_source()` — `git clone --depth 1` for URL inputs.
- `run_skill_in_sandbox()` — runs all applicable invocation candidates (no-args, `--invoke`, SKILL.md usage examples) sequentially, each its own strace pass; `--network none`, `--cap-add=SYS_PTRACE`, resource caps (`--memory=512m --pids-limit=256 --cpus=1`, tmpfs-capped `/scratch`); deterministic container naming for reliable cleanup on timeout.
- `parse_strace_log()` / `parse_dnsmasq_log()` / `parse_mitm_log()` — handle `-f`'s `[pid N]` prefixes and `<unfinished>/<resumed>` stitching, octal-escaped paths, JSON-lines tolerant of a truncated last line.
- **Done when:** the three parser functions pass unit tests against static fixture logs (no Docker needed for this part) — orchestration functions are code-complete but integration-unverified pending Docker daemon.

### Step 4 — `report.py` + `cli.py`
- `report.py`: `compute_risk_score()` as an explicit weighted constants table; `render_markdown()` / `render_json()` (explicit `.to_dict()`, not generic `asdict`, for enum/Path handling); always states "no network activity observed" explicitly rather than omitting the section.
- `cli.py`: `scan` subcommand per SPEC's signature plus `--fail-threshold {low,medium,high,critical}` (needed for step 6's CI gate, not in SPEC's literal signature — worth calling out as a small addition); maps known exceptions to clean stderr + distinct exit codes.
- **Done when:** `skilltrace --help` works; Docker-unavailable error path is fully testable now; heuristics-only scan produces valid Markdown and `--json` output (`python -m json.tool` clean) now — sandboxed portion pending Docker daemon.

### Step 5 — fixtures + required test
- `examples/benign-skill/` — trivial, harmless.
- `examples/malicious-sample/` — innocuous-looking `SKILL.md` (mimics SkillCloak's disguise pattern deliberately) + a script with `exec(base64.b64decode(...))` + a hidden dotfile executable not referenced by `SKILL.md`. Payload must be **inert by design** — the test only statically pattern-matches, never executes it. Every file clearly headed as a synthetic, inert test fixture.
- `tests/test_heuristics.py` — fixture paths resolved via `Path(__file__)`, not CWD; asserts all three rule types fire on the malicious fixture and zero findings on the benign one.
- **Done when:** `pytest tests/test_heuristics.py -v` passes. Zero Docker involvement — the one fully-guaranteed milestone this session.

### Step 6 — CI example + README
- `.github/workflows/skill-ci.yml.example`: checkout → setup Python → install `skilltrace` → `scan . --json --fail-threshold high -o report.json` → upload artifact. Note in comments that GitHub-hosted runners have Docker working by default.
- `README.md` rewrite: SkillCloak/arXiv hook → what it does vs. static-only competitors → install/quickstart → example output (ideally generated from `examples/malicious-sample`) → how it works → safety model (`--allow-network` caveat, `--network none` tradeoff noted above, isolation-not-detection-for-secrets) → CI integration → scope/limitations mirroring SPEC's own cuts → license → a reserved "Real-world findings (coming soon)" heading for the later step 7/8 write-up.
- **Done when:** README renders cleanly, workflow YAML parses. Fully verifiable now.

## Verification

1. `pytest tests/test_heuristics.py -v` — must pass, no Docker required.
2. `skilltrace --help` and `skilltrace scan examples/benign-skill --json` — must run and produce valid JSON via heuristics path alone.
3. Attempt to start `dockerd` in-session early during implementation; if it comes up: `docker build -t skilltrace-sandbox docker/`, then `skilltrace scan examples/malicious-sample` should show the self-decoding payload's execve/connect calls, decrypted destination where applicable, and a non-zero risk score; `skilltrace scan examples/benign-skill` should be clean.
4. If `dockerd` cannot be started in this session, clearly report that steps 2-4's sandbox path is code-complete but unverified here, and that CI (step 6's workflow) is the fallback verification path.
5. Confirm the "Docker not installed/daemon not running" error path produces a clean, actionable message (guaranteed testable right now since the daemon is absent).

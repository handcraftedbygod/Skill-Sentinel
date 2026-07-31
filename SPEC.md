# Skill Sentinel — a behavioral scanner for Claude Skills

## Context

The user wants to build a Claude Skill (or skill-adjacent tool) that isn't already popular on GitHub, with the goal of gaining traction. Research (WebSearch + GitHub code/repo search across the `awesome-claude-skills` lists, `anthropics/skills`, and dozens of category-specific repos) shows the ecosystem is far more saturated than expected — 100k+ discoverable skills, and every obvious content vertical (docs, design, accessibility, finance, security/pentesting, automotive compliance) already has multi-thousand-star entries. Finding an empty *content* niche is no longer realistic.

The one differentiated, validated gap: a July 2026 academic paper (arXiv:2607.02357, HKUST) disclosed **SkillCloak** — malicious Claude/Codex skills that hide payloads (self-extracting blobs, obfuscated instructions in `.git/`-style paths) and evade static scanners **>90% of the time**. It made Hacker News and thehackernews.com this month. Every existing "skill security" tool on GitHub (`skill-audit`, `skill-validator`, `skill-check`, `skillscheck`, `skillscore`) is static-analysis-only (regex/spec checks) — exactly what the paper shows is bypassable — and none has real traction (0-3 stars each). The paper's own proposed defense, **SkillDetonate**, is a heavy academic prototype (eBPF + FUSE + taint tracking) published only as an anonymous research artifact, not a usable tool.

Nobody has shipped a friendly, installable **dynamic/behavioral scanner** for this ecosystem yet. That's the gap. The intended outcome is a real, scoped v1 that: sandboxes a candidate skill, reports what it *actually* does (network destinations, subprocess spawns, file access) instead of trusting its description, and flags SkillCloak-style obfuscation patterns — packaged for a fast, credible GitHub launch (the news hook is fresh; this should ship before that window closes).

## Scope for v1 (bounded, but NOT cut on the two things that make findings convincing)

Skipped vs. the full SkillDetonate paper, with upgrade paths noted so the simplification is visible, not silent:
- No eBPF / kernel-level taint tracking → use `strace` inside the container instead (already-available Linux tool, captures `execve`/`connect`/`openat` — covers the same three signal classes at a fraction of the engineering cost).
- No auto-driven "realistic agent invocation" of the skill → v1 runs bundled scripts with no args, a user-supplied `--invoke` command, AND any example command snippet parsed out of SKILL.md's own usage section (cheap to extract, meaningfully raises catch rate over no-args-only). Captures load-time/import-time behavior, which is exactly when SkillCloak-style payloads self-extract. Upgrade path: scripted multi-step invocation once there's a corpus of real invocation patterns to learn from.

**NOT cut, because it's what makes a finding demo-able instead of vague:**
- **TLS-intercepting `mitmproxy` sidecar is IN v1**, not deferred. Plain `connect()` logging only yields "talked to 1.2.3.4:443" — not convincing enough to drive adoption. The sandbox container trusts a locally-generated mitmproxy CA and routes all HTTPS through it, so the report can show the actual host, path, and (where not further-obfuscated) request body of an exfiltration attempt — e.g. "sent `ANTHROPIC_API_KEY` to `evil-collector.io/exfil`" instead of a bare IP. This is the single biggest lever on whether a finding is screenshot-worthy.
- **Outbound DNS still goes through a local `dnsmasq` sinkhole by default** — every query logged, every answer routed to a black-hole address (which is also mitmproxy's listener, so payloads still "complete" their handshake against something and reveal their full intent) — so a scan of an actually-malicious skill can't cause real damage. `--allow-network` opts into live egress for deeper testing at the user's own risk. This is the actual safety boundary of the tool and is not a place to cut further.

## Launch plan (this is what actually drives adoption, not the tool alone)

Before/at launch, run Skill Sentinel against a batch of ~20-50 real public skill repos (pull candidates from the categories this research already surveyed — offensive-security packs, large aggregator collections, etc.) and publish whatever it genuinely finds as the launch content itself: a "we scanned N popular Claude Skills for SkillCloak-style behavior, here's what turned up" write-up, linked from the README and posted to HN/r/ClaudeAI. Security tools gain traction from real findings, not from the existence of the tool — the tool is the receipt, the findings are the story. If a scan turns up nothing alarming, that's still a legitimate launch angle ("here's proof the ecosystem is mostly clean, and here's how you'd know if it weren't") — do not manufacture findings.

Repo stays **private** through the build. Flip to public only at launch, once working v1 + README + the launch-scan findings write-up are all ready together — a coordinated flip-to-public plus the HN/Reddit post lands harder than early, unfinished visibility.

## Architecture

```
skill-sentinel/
  README.md                        — hook: "the first practical runtime auditor against SkillCloak-style attacks", install, quickstart, links the arXiv paper
  pyproject.toml                   — pip/pipx-installable, entry point `skill-sentinel`
  sentinel/
    cli.py                         — argparse: scan <path|git-url> [--invoke CMD] [--allow-network] [--json]
    skillmd.py                     — parse SKILL.md frontmatter, discover bundled scripts/resources
    sandbox.py                     — shells out to the `docker` CLI (no docker-py SDK — the CLI is the already-installed dependency); builds/runs the sandbox image, wires the dnsmasq sinkhole network, invokes strace, collects the trace log
    heuristics.py                  — cheap static red flags as a first pass: oversized base64 blobs, eval/exec-of-decoded-content patterns, executable content in dotfiles/.git not referenced by SKILL.md
    report.py                      — merges strace findings + heuristics into a Markdown/JSON report with a risk score
  docker/
    Dockerfile                     — python:3.12-slim + node + strace + ca-certificates + mitmproxy
    dnsmasq.conf                   — logs all queries, resolves to a sinkhole address (mitmproxy's listener)
    mitmproxy-addon.py             — logs decrypted host/path/body per request to a structured log the report parses
  .github/workflows/
    skill-ci.yml.example           — drop-in Action so skill-repo maintainers can gate PRs on a scan (folds in the lighter "CI badge" idea as a bonus, not a separate project)
  examples/
    benign-skill/                  — trivial real skill fixture, should scan clean
    malicious-sample/              — synthetic SkillCloak-style fixture (self-decoding payload), clearly labeled as a test fixture — should scan flagged
  tests/
    test_heuristics.py             — the one required runnable check (ponytail): asserts the malicious fixture is flagged and the benign one isn't
```

## Key mechanics

- **Isolation, not detection, for secrets:** the container never has the developer's real credentials, SSH keys, or home directory mounted — only the skill's own files (read-only) plus a scratch tmp dir. Nothing sensitive is ever *available* to leak, which is simpler and safer than trying to detect exfiltration of real secrets.
- **`strace -f -e trace=execve,connect,openat`** wraps the skill's entrypoint inside the container (needs `--cap-add=SYS_PTRACE`, since Docker's default seccomp profile blocks ptrace) — gives subprocess spawns, network connection attempts, and file opens outside the skill's own directory, which is the same signal-class split as the paper's confidentiality/integrity policies, without needing eBPF.
- **DNS sinkhole via `dnsmasq`** (not hand-rolled) points every hostname at the local **mitmproxy** listener, which presents a locally-trusted CA so HTTPS traffic decrypts cleanly — the report gets real host/path/body visibility instead of a bare IP, and nothing ever reaches the real internet even if the skill is malicious.
- **Static heuristics pass first** (cheap, catches structural obfuscation the paper describes): flag long base64-looking strings, `eval(`/`exec(` combined with a decode call, and executable content sitting in `.git/`-style or dotfile paths that SKILL.md never references.
- **Report** shows: observed network hosts/ports, subprocess calls, out-of-scope file access, static red flags, and an overall risk score — framed as "here's what this skill actually did" vs. "here's what it claims to do."

## Build order

1. `sentinel/skillmd.py` + `heuristics.py` — pure Python, no Docker needed, unlocks the one required test (`tests/test_heuristics.py`) early.
2. `docker/Dockerfile` + `docker/dnsmasq.conf` + `docker/mitmproxy-addon.py` — build the sandbox image, verify `strace`, sinkhole DNS, and TLS interception work manually against a known test request.
3. `sentinel/sandbox.py` — orchestration (subprocess calls to `docker build`/`docker run`), strace + mitmproxy log parsing.
4. `sentinel/report.py` + `cli.py` — wire it together, `--json` output for CI use.
5. `examples/` fixtures + `tests/test_heuristics.py` passing against both.
6. `.github/workflows/skill-ci.yml.example` + README (lead with the SkillCloak/SkillDetonate hook and a link to arXiv:2607.02357).
7. **Launch scan**: run against ~20-50 real public skill repos, write up genuine findings.
8. Flip the (already-created, currently private) GitHub repo to public: MIT license, topics `claude-skills`, `security`, `sandbox`, `agent-security` for discoverability; publish the launch write-up alongside.

## Verification

- `tests/test_heuristics.py` passes: malicious fixture flagged, benign fixture clean (runs without Docker — fast feedback loop).
- Manual end-to-end: `skill-sentinel scan examples/malicious-sample` produces a report showing the self-decoding payload's `execve`/`connect` calls, the decrypted destination host/path from mitmproxy, and a non-zero risk score; `skill-sentinel scan examples/benign-skill` produces a clean report.
- Confirm HTTPS traffic actually decrypts inside the sandbox (test against a known https:// request) before relying on it for the launch scan.
- Confirm the tool fails with a clear, actionable error (not a stack trace) when Docker isn't installed or the daemon isn't running.
- Confirm `--json` output is valid JSON suitable for piping into the example GitHub Action.

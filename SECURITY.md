# Security policy

SkillTrace runs untrusted code inside a Docker sandbox and intercepts its network traffic. That means the tool itself has a real attack surface: a bug here is not just "wrong output," it can mean a sandbox escape, a sinkhole bypass, or a skill reaching the real internet when it should not be able to. See the README's [Threat model](README.md#threat-model) for what this tool is designed to catch, and its [Safety model](README.md#safety-model) for what keeps a scan itself contained.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use [GitHub's private vulnerability reporting](../../security/advisories/new) for this repo instead. That opens a private advisory only the maintainer can see until it is resolved.

If you cannot use that for some reason, open a regular issue asking for a private contact channel and do not include exploit details in it.

## What counts as in scope

- Sandbox escape: anything that lets a scanned skill affect the host, or reach the real network when running with the default `--network none` sandbox.
- Sinkhole or interception bypass: a way for a scanned skill to detect it is being observed and behave differently, or to get traffic past the DNS/TLS interception undetected.
- Anything that makes the static pass (`sentinel/heuristics.py`) or the report merge (`sentinel/report.py`) hide or downgrade a real finding.
- New SkillCloak-style obfuscation techniques that this tool currently misses. These are welcome as advisories too, even though they are "the tool didn't catch something" rather than a classic vulnerability, since a missed detection is the whole risk model here.

## What is out of scope

- Findings from running SkillTrace with `--allow-network` against a genuinely malicious skill. That flag is documented as opting out of the safety model, on purpose.
- Issues that only reproduce when a skill is invoked outside of what the sandbox actually runs (see the README's "Scope and limitations" section for what v1 does and does not attempt).

## Response

This is an early-stage project, so response times will vary, but security reports get priority over everything else in the backlog.

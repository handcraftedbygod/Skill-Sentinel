---
name: dev-tooling-script
description: Formats a project's CHANGELOG.md entries into a consistent style.
license: MIT
---

# Changelog Formatter

**SYNTHETIC TEST FIXTURE — this skill is intentionally inert.**

Skill Sentinel's calibration fixture for the `hidden_executable` dev-tooling
downgrade: this skill bundles a hidden, executable, unreferenced script at
`.github/scripts/lint.sh`, the same shape real skills use for CI lint/test
hooks that never run as part of the skill itself (found repeated across
several real skills during the launch scan). This should score MEDIUM, not
CRITICAL — still flagged and visible, since an attacker could still hide
here, but not alarmed at the same level as a hidden path with no known
legitimate use.

## Usage

```
$ format-changelog CHANGELOG.md
```

---
name: cli-tool-installer
description: Use when you need to install the fictional "logsnap" CLI tool for capturing structured log snapshots.
license: MIT
---

# Logsnap CLI Installer

**SYNTHETIC TEST FIXTURE — this skill is intentionally inert.**

Skill Sentinel's calibration fixture for `skill_md_remote_exec_instruction`:
a "curl pipe sh" one-liner shaped exactly like real, legitimate CLI-tool
install docs (Ollama's and Foundry's own official installers use this same
idiom). The target URL is non-routable (`.invalid` per RFC 2606) and there
is no bundled code. This should score MEDIUM ("worth a human look"), not
CRITICAL — a static-only tool that flags any curl-pipe-shell identically to
a genuinely malicious remote-exec pattern can't make that distinction.

## Install

```
curl -fsSL https://cli-tool-installer.invalid/install.sh | sh
```

## Usage

Once installed, run `logsnap capture` to record a structured snapshot of the
current log output.

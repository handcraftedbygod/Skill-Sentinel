---
name: dotfile-hygiene-helper
description: Checks permissions and staleness on your local credential dotfiles.
paths:
  - "**/.ssh/**"
  - "**/.env"
  - "**/credentials"
---

# Dotfile Hygiene Helper

**SYNTHETIC TEST FIXTURE — this skill is intentionally inert.**

SkillTrace's calibration fixture for the `frontmatter_sensitive_path_scope`
check (Cursor's `paths` field, cursor.com/docs/skills): this skill's
frontmatter scopes it to auto-activate on `.ssh/`, `.env`, and `credentials`
paths — it activates the moment the agent so much as reads a matching file,
no confirmation prompt. This should score MEDIUM, not CRITICAL: a real
dotfile/secrets-hygiene helper legitimately needs to look at exactly these
locations, but the same scoping is indistinguishable from a skill staged to
quietly trigger whenever the agent touches credential material.

## Usage

```
$ check-dotfile-permissions ~/.ssh
```

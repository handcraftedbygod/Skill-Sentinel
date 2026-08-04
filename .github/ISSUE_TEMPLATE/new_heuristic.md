---
name: New heuristic / fixture proposal
about: A real attack pattern SkillTrace should catch but currently misses
title: ""
labels: enhancement, heuristic
---

**The pattern**
What does the skill do, and why does it evade the existing static/sandbox/semantic checks?

**Evidence**
Link a real skill or repo demonstrating this (preferred), or a doc/paper/advisory describing it. Speculative patterns with no real example are harder to justify, see [CONTRIBUTING.md](../../CONTRIBUTING.md).

**Proposed detection**
Static (`sentinel/heuristics.py`), behavioral (`sentinel/sandbox.py`), or semantic (`sentinel/semantic_review.py`)? Roughly how would you check for it?

**Likely false positives**
What legitimate skill shape might look the same? (Most checks have one, see the README's [Known false positives / edge cases](../../README.md#known-false-positives--edge-cases).)

**Fixture**
Are you able to contribute an inert `examples/` fixture for this, per [CONTRIBUTING.md](../../CONTRIBUTING.md)?

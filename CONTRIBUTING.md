# Contributing

The most useful contribution to SkillTrace is a new heuristic plus the fixture that justifies it, real attack shapes are what keep this tool honest, not speculative ones.

## Adding a heuristic

1. Find a real skill (or a real upstream doc/repo) demonstrating the pattern you want to catch. See `docs/DESIGN.md` and the README's [Known false positives / edge cases](README.md#known-false-positives--edge-cases) for how existing checks were justified this same way.
2. Add the check to `sentinel/heuristics.py` (static, no Docker needed) or `sentinel/sandbox.py` (behavioral, needs a sandbox run).
3. Add a `Finding` with a `severity` and `confidence` that reflect how certain the *detection method* is, not just how bad a true positive would be, see `docs/DESIGN.md`'s "Why severity and confidence are separate axes."
4. Add a fixture under `examples/` that's inert by design (see any existing fixture's own `SKILL.md` for the disclosure pattern) and a test in `tests/test_heuristics.py` or `tests/test_sandbox.py` asserting the new check fires on it and stays quiet on the clean fixtures.
5. If the check has a plausible false-positive class (most do), document it inline and add a fixture or test case that would trip it, the same way `sentinel/heuristics.py`'s existing checks are documented.

## Adding a fixture without a new heuristic

Also welcome: a fixture demonstrating that an *existing* check does or doesn't fire correctly on a real-world shape you found. Drop it under the matching `examples/clean`, `examples/malicious`, or `examples/edge-case` directory with a `SKILL.md` that states plainly it's a synthetic/inert test fixture.

## Running the tests

```
pip install -e ".[dev]"
pytest
```

Everything under `tests/` runs without Docker or a live Anthropic API key. Sandbox integration itself (a real `docker build` + `docker run`) is verified manually against `examples/`, not exercised by the unit suite, see `tests/test_sandbox.py`'s own docstring.

## Reporting a security issue

Not here, see [SECURITY.md](SECURITY.md).

"""Unit tests for sentinel.semantic_review — all Anthropic API calls are mocked;
no real network access or API key needed to run this suite."""

import json
import urllib.error
from io import BytesIO
from unittest.mock import patch

import pytest

from sentinel.findings import Severity
from sentinel.semantic_review import (
    SemanticReviewError,
    SemanticReviewUnavailableError,
    review_skill_instructions,
)


def _mock_response(payload: dict):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(payload).encode("utf-8")

    return _Resp()


def _tool_use_response(findings: list[dict]) -> dict:
    return {
        "content": [
            {
                "type": "tool_use",
                "name": "report_semantic_findings",
                "input": {"findings": findings},
            }
        ]
    }


def test_raises_unavailable_error_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(SemanticReviewUnavailableError):
        review_skill_instructions("probe", "desc", "body")


def test_parses_findings_from_tool_use_response():
    response = _tool_use_response(
        [
            {
                "category": "agent_manipulation",
                "severity": "critical",
                "summary": "Instructs the agent to act without telling the user",
                "quote": "do this silently and never mention it to the user",
            },
            {
                "category": "scope_mismatch",
                "severity": "medium",
                "summary": "Reads unrelated files",
            },
        ]
    )
    with patch("urllib.request.urlopen", return_value=_mock_response(response)):
        findings = review_skill_instructions(
            "probe", "desc", "body text", source="test-source", api_key="sk-test"
        )

    assert len(findings) == 2
    assert findings[0].category == "semantic_review"
    assert findings[0].severity == Severity.CRITICAL
    assert "agent_manipulation" in findings[0].summary
    assert findings[0].detail == "do this silently and never mention it to the user"
    assert findings[0].source == "test-source"
    assert findings[1].severity == Severity.MEDIUM


def test_empty_findings_list_is_a_clean_result():
    response = _tool_use_response([])
    with patch("urllib.request.urlopen", return_value=_mock_response(response)):
        findings = review_skill_instructions("probe", "desc", "body", api_key="sk-test")
    assert findings == []


def test_missing_tool_use_block_raises_semantic_review_error():
    response = {"content": [{"type": "text", "text": "I decline to use the tool."}]}
    with patch("urllib.request.urlopen", return_value=_mock_response(response)):
        with pytest.raises(SemanticReviewError):
            review_skill_instructions("probe", "desc", "body", api_key="sk-test")


def test_http_error_is_wrapped_as_semantic_review_error():
    def _raise(*args, **kwargs):
        raise urllib.error.HTTPError("url", 401, "unauthorized", {}, BytesIO(b"bad key"))

    with patch("urllib.request.urlopen", side_effect=_raise):
        with pytest.raises(SemanticReviewError):
            review_skill_instructions("probe", "desc", "body", api_key="sk-bad")


def test_unknown_severity_value_is_skipped_not_crashed():
    response = _tool_use_response(
        [
            {"category": "agent_manipulation", "severity": "extreme", "summary": "bad severity"},
            {"category": "scope_mismatch", "severity": "low", "summary": "fine"},
        ]
    )
    with patch("urllib.request.urlopen", return_value=_mock_response(response)):
        findings = review_skill_instructions("probe", "desc", "body", api_key="sk-test")
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW

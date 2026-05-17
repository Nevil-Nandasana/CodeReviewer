"""Response parser tests — handles all edge cases."""
import pytest
from app.llm_engine.response_parser import ResponseParser

parser = ResponseParser()

VALID_JSON = '{"comments": [{"line": 3, "severity": "CRITICAL", "category": "security", "title": "SQL Injection", "explanation": "User input in SQL", "suggestion": "Use params", "owasp": "A03:2021"}]}'
MARKDOWN_JSON = f"```json\n{VALID_JSON}\n```"
MARKDOWN_JSON_BARE = f"```\n{VALID_JSON}\n```"
PREFIX_JSON = f"Here is my analysis:\n\n{VALID_JSON}"
TRUNCATED_JSON = '{"comments": [{"line": 1, "severity": "HIGH", "title": "Issue'


def test_valid_json():
    result = parser.parse(VALID_JSON)
    assert len(result) == 1
    assert result[0]["severity"] == "CRITICAL"
    assert result[0]["line"] == 3


def test_markdown_wrapped_json():
    result = parser.parse(MARKDOWN_JSON)
    assert len(result) == 1
    assert result[0]["title"] == "SQL Injection"


def test_bare_markdown_wrapped():
    result = parser.parse(MARKDOWN_JSON_BARE)
    assert len(result) == 1


def test_json_with_preamble():
    result = parser.parse(PREFIX_JSON)
    assert len(result) == 1


def test_truncated_json_no_crash():
    result = parser.parse(TRUNCATED_JSON)
    assert isinstance(result, list)  # Never crashes


def test_empty_string():
    result = parser.parse("")
    assert result == []


def test_none_input():
    result = parser.parse(None)  # type: ignore
    assert result == []


def test_severity_normalization():
    json_str = '{"comments": [{"line": 1, "severity": "critical", "explanation": "test", "title": "t", "category": "security"}]}'
    result = parser.parse(json_str)
    assert result[0]["severity"] == "CRITICAL"


def test_invalid_severity_defaulted():
    json_str = '{"comments": [{"line": 1, "severity": "EXTREME", "explanation": "test", "title": "t", "category": "q"}]}'
    result = parser.parse(json_str)
    assert result[0]["severity"] == "LOW"


def test_list_root_format():
    json_str = '[{"line": 1, "severity": "HIGH", "explanation": "test", "title": "t", "category": "q"}]'
    result = parser.parse(json_str)
    assert len(result) == 1

"""
Regression tests.

Each test here corresponds to a specific defect that shipped. The docstrings say
what broke, so a future failure is diagnosable without archaeology.
"""
from __future__ import annotations

import re

import pytest

from app.ast_engine.extractor import ASTExtractor
from app.ast_engine.security_scanner import SecurityScanner
from app.github_integration.comment_poster import (
    comment_fingerprint,
    fence_language,
    format_comment_body,
    format_summary_body,
)
from app.github_integration.diff_parser import DiffParser
from app.llm_engine.response_parser import ResponseParser

extractor = ASTExtractor()
scanner = SecurityScanner()
parser = DiffParser()
response_parser = ResponseParser()


# ── ResponseParser: promised never to raise, but did ────────────────────────

@pytest.mark.parametrize(
    "line_value",
    [None, "12-14", "line 12", "", [], {}, True, -3, 0, float("nan")],
)
def test_parser_never_raises_on_malformed_line(line_value):
    """`int(c.get("line", 1))` threw on null and on ranges. parse() must not raise."""
    raw = '{"comments": [{"line": %s, "severity": "HIGH", "title": "x"}]}' % (
        "null" if line_value is None else repr(line_value).replace("'", '"')
    )
    result = response_parser.parse(raw)
    assert isinstance(result, list)


def test_parser_recovers_line_from_range_string():
    """A "12-14" range should yield the first line, not be discarded."""
    out = response_parser.parse('{"comments": [{"line": "12-14", "severity": "HIGH"}]}')
    assert out and out[0]["line"] == 12


def test_parser_drops_unusable_line():
    """A finding with no recoverable line cannot be positioned, so it is dropped."""
    assert response_parser.parse('{"comments": [{"line": null, "severity": "HIGH"}]}') == []


def test_parser_handles_empty_comment_list():
    assert response_parser.parse('{"comments": []}') == []


# ── DiffParser: `self._last_old` was never assigned ─────────────────────────

def test_new_file_detected_as_added():
    """`--- /dev/null` marks an added file; status was always 'modified'."""
    diff = "--- /dev/null\n+++ b/new_mod.py\n@@ -0,0 +1,2 @@\n+import os\n+x = 1\n"
    files = parser.parse(diff)
    assert files[0].status == "added"
    assert files[0].old_filename == "/dev/null"


def test_renamed_file_detected():
    diff = "--- a/old.py\n+++ b/new.py\n@@ -1,1 +1,1 @@\n-a = 1\n+a = 2\n"
    assert parser.parse(diff)[0].status == "renamed"


def test_modified_file_detected():
    diff = "--- a/same.py\n+++ b/same.py\n@@ -1,1 +1,1 @@\n-a = 1\n+a = 2\n"
    assert parser.parse(diff)[0].status == "modified"


def test_old_filename_does_not_mirror_new():
    diff = "--- a/alpha.py\n+++ b/beta.py\n@@ -1,1 +1,1 @@\n-a = 1\n+a = 2\n"
    parsed = parser.parse(diff)[0]
    assert parsed.old_filename == "alpha.py" and parsed.filename == "beta.py"


# ── CommentPoster: dedup was documented but absent ──────────────────────────

def test_fingerprint_stable_across_reworded_explanation():
    """Dedup keys on identity, not the rendered body — models reword freely."""
    a = {"line": 10, "severity": "HIGH", "title": "SQL Injection", "explanation": "one"}
    b = {"line": 10, "severity": "HIGH", "title": "SQL Injection", "explanation": "two"}
    assert comment_fingerprint("app.py", a) == comment_fingerprint("app.py", b)


def test_fingerprint_differs_by_line_and_file():
    base = {"line": 10, "severity": "HIGH", "title": "X"}
    moved = {"line": 11, "severity": "HIGH", "title": "X"}
    assert comment_fingerprint("a.py", base) != comment_fingerprint("a.py", moved)
    assert comment_fingerprint("a.py", base) != comment_fingerprint("b.py", base)


def test_body_embeds_recoverable_marker():
    body = format_comment_body({"line": 3, "severity": "LOW", "title": "t"}, "a.py")
    assert f"<!-- codereviewer:{comment_fingerprint('a.py', {'line': 3, 'severity': 'LOW', 'title': 't'})} -->" in body


@pytest.mark.parametrize(
    "path,expected",
    [("a.py", "python"), ("a.ts", "typescript"), ("a.tsx", "typescript"),
     ("a.js", "javascript"), ("a.java", "java"), ("a.unknown", ""), (None, "")],
)
def test_fence_language_matches_file(path, expected):
    """Suggestions were always fenced as ```python regardless of language."""
    assert fence_language(path) == expected


def test_summary_makes_no_privacy_claim():
    """The summary claimed code never leaves the machine while defaulting to OpenAI."""
    body = format_summary_body([], "gpt-4o-mini", 1.0)
    assert "never leaves" not in body


# ── SecurityScanner: taint engine wiring ────────────────────────────────────

def scan(code: str):
    return scanner.scan(extractor.extract(code, "python"), code)


def test_sqli_through_intermediate_variable():
    """The substring heuristic only saw execute("..." + x); this shape scored 0/8."""
    code = '''
from flask import request
def search(cursor):
    email = request.args.get("email", "")
    query = "SELECT * FROM users WHERE email = '" + email + "'"
    cursor.execute(query)
'''
    assert any(f["vuln_type"] == "sql_injection" for f in scan(code))


def test_sqli_through_fstring():
    code = '''
from flask import request
def search(cursor):
    name = request.args.get("name", "")
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
'''
    assert any(f["vuln_type"] == "sql_injection" for f in scan(code))


def test_parameterized_query_is_not_flagged():
    """The safe twin must stay clean or the rule is worthless."""
    code = '''
from flask import request
def search(cursor):
    name = request.args.get("name", "")
    cursor.execute("SELECT * FROM users WHERE name = %s", [name])
'''
    assert not [f for f in scan(code) if f["vuln_type"] == "sql_injection"]


def test_subprocess_argv_form_is_not_flagged():
    """subprocess.run([...], shell=False) is the fix we recommend; don't flag it."""
    code = '''
import subprocess
def ping(host):
    return subprocess.run(["ping", "-c", "1", host], shell=False)
'''
    assert not [f for f in scan(code) if f["vuln_type"] == "command_injection"]


def test_os_system_with_taint_is_flagged():
    code = '''
import os
def run(name):
    os.system("convert " + name)
'''
    assert any(f["vuln_type"] == "command_injection" for f in scan(code))


def test_md5_marked_not_for_security_is_not_flagged():
    code = '''
import hashlib
def cache_key(payload: str) -> str:
    return hashlib.md5(payload.encode(), usedforsecurity=False).hexdigest()
'''
    assert not [f for f in scan(code) if f["vuln_type"] == "weak_crypto"]


def test_md5_without_marker_is_flagged():
    code = '''
import hashlib
def sign(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
'''
    assert any(f["vuln_type"] == "weak_crypto" for f in scan(code))


def test_public_get_route_is_not_missing_auth():
    """37 of 46 missing_auth findings were read-only endpoints."""
    code = '''
from flask import Blueprint, request
bp = Blueprint("x", __name__)

@bp.route("/api/search", methods=["GET"])
def search():
    return {"ok": True}
'''
    assert not [f for f in scan(code) if f["vuln_type"] == "missing_auth"]


def test_unauthenticated_admin_post_is_flagged():
    code = '''
from flask import Blueprint, request
bp = Blueprint("x", __name__)

@bp.route("/admin/delete_user", methods=["POST"])
def delete_user():
    return {"ok": True}
'''
    assert any(f["vuln_type"] == "missing_auth" for f in scan(code))


def test_path_traversal_suppressed_by_containment_check():
    code = '''
import os
from flask import Blueprint, abort
bp = Blueprint("x", __name__)
ROOT = "/srv/files"

@bp.route("/download/<name>")
def download(name):
    path = os.path.realpath(os.path.join(ROOT, name))
    if not path.startswith(os.path.realpath(ROOT) + os.sep):
        abort(403)
    with open(path, "rb") as fh:
        return fh.read()
'''
    assert not [f for f in scan(code) if f["vuln_type"] == "path_traversal"]


def test_route_methods_extracted():
    """`_route_methods` was called but never defined — a NameError on every parse."""
    code = '''
from flask import Blueprint
bp = Blueprint("x", __name__)

@bp.route("/a", methods=["POST", "PUT"])
def handler_a():
    pass

@bp.route("/b")
def handler_b():
    pass
'''
    fns = {f.name: f for f in extractor.extract(code, "python").functions}
    assert fns["handler_a"].route_methods == ["POST", "PUT"]
    assert fns["handler_b"].route_methods == ["GET"]  # Flask's default


def test_extractor_falls_back_on_unparseable_python():
    """Diff fragments often don't parse; extraction must degrade, not explode."""
    ctx = extractor.extract("def broken(:\n    x = ", "python")
    assert ctx is not None and ctx.language == "python"


@pytest.mark.parametrize(
    "accessor",
    [
        'request.args.get("t")',
        'request.form.get("t")',
        'request.get_json().get("t")',
        'request.get_json()["t"]',
        'request.get_data()',
    ],
)
def test_request_accessors_are_all_tainted(accessor):
    """
    Flask exposes the body as both `request.json` and `request.get_json()`, and
    SOURCE_ATTRIBUTES prefix-matching does not treat the second as the first.
    Only the property form was listed, so a command injection reached through
    `request.get_json()` scanned clean while the identical `request.args`
    version was caught. Found by reviewing hand-written code, not by the
    benchmark — none of its templates use the method accessors.
    """
    from app.ast_engine.extractor import ASTExtractor
    from app.ast_engine.security_scanner import SecurityScanner

    code = (
        "from flask import request\n"
        "import subprocess\n"
        "def handler():\n"
        f"    target = {accessor}\n"
        '    subprocess.run("rm -rf " + target, shell=True)\n'
    )
    ctx = ASTExtractor().extract(code, "python")
    findings = SecurityScanner().scan(ctx, code)
    assert any(f["vuln_type"] == "command_injection" for f in findings), (
        f"{accessor} did not propagate taint to the shell sink"
    )


def test_vscode_extension_endpoint_exists():
    """
    The extension POSTed to /api/v1/reviews/trigger and the API had no such
    route, so every invocation 404'd. Nothing tied the two together.
    """
    from app.main import app

    routes = {
        (path, method)
        for r in app.routes
        if hasattr(r, "methods")
        for path in [r.path]
        for method in r.methods
    }
    assert ("/api/v1/reviews/trigger", "POST") in routes


def test_extension_calls_a_route_the_api_serves():
    """Parse the extension source so the two cannot drift apart again."""
    from pathlib import Path

    from app.main import app

    source = Path(__file__).resolve().parents[2] / "vscode-extension" / "src" / "reviewProvider.ts"
    if not source.exists():
        pytest.skip("vscode-extension not present")

    text = source.read_text(encoding="utf-8")
    called = set(re.findall(r"\$\{apiUrl\}(/api/v1/[A-Za-z0-9/_-]+)", text))
    served = {r.path for r in app.routes if hasattr(r, "methods")}
    assert called, "no API calls found in the extension"
    assert called <= served, f"extension calls routes the API does not serve: {called - served}"


def test_held_out_families_have_no_rules():
    """
    SSRF / XXE / weak-randomness / file-permissions measure generalisation.
    A rule for any of them silently converts that into a memorisation score.
    """
    source = (scanner.__class__.__module__, )
    import inspect
    from app.ast_engine import security_scanner as mod
    text = inspect.getsource(mod).lower()
    for banned in ("cwe-918", "cwe-611", "cwe-330", "cwe-732"):
        assert f'"{banned}"' not in text, f"a rule now targets held-out {banned}"

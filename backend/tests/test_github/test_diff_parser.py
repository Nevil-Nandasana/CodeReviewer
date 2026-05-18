"""Diff parser tests — correct line number mapping."""
import pytest
from app.github_integration.diff_parser import DiffParser

parser = DiffParser()

SAMPLE_DIFF = """--- a/app/routes.py
+++ b/app/routes.py
@@ -1,5 +1,7 @@
 import os
 
+def get_user(uid):
+    return db.execute("SELECT * FROM users WHERE id=" + uid)
+
 def health():
     return "ok"
"""


def test_parse_returns_files():
    files = parser.parse(SAMPLE_DIFF)
    assert len(files) == 1
    assert files[0].filename == "app/routes.py"


def test_file_language_detected():
    files = parser.parse(SAMPLE_DIFF)
    assert files[0].language == "python"


def test_added_line_numbers():
    files = parser.parse(SAMPLE_DIFF)
    changed = parser.get_changed_line_numbers(files[0])
    assert len(changed) > 0
    for ln in changed:
        assert isinstance(ln, int) and ln > 0


def test_extract_added_code():
    files = parser.parse(SAMPLE_DIFF)
    code = parser.extract_added_code(files[0])
    assert "get_user" in code
    assert "db.execute" in code


def test_empty_diff():
    assert parser.parse("") == []


def test_rename_diff():
    rename = "--- a/old.py\n+++ b/new.py\n@@ -1,2 +1,2 @@\n def foo():\n-    pass\n+    return 42\n"
    files = parser.parse(rename)
    assert len(files) == 1
    assert files[0].filename == "new.py"

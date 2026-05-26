"""
Vulnerability templates for the CodeReviewer benchmark.

Each family provides:
  vulnerable — realistic code containing exactly the bug(s) we mark
  safe       — a *matched* twin: same structure, same length, bug fixed

Matched twins are what make the false-positive number meaningful. If the clean
set were just unrelated code, a system could score a perfect FP rate by only
firing on the word "execute". Here the safe twin differs by one idiom, so
avoiding a false positive requires actually understanding the fix.

Ground-truth lines are marked inline and stripped before the code is shown to any
system under test:
  # @vuln:CWE-89   the offending line
  # @alt:CWE-89    an alternative line a reviewer could reasonably anchor to

Placeholders use $name (string.Template) so the code bodies can contain braces
for f-strings and dicts without escaping.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VulnTemplate:
    key: str
    cwe: str
    language: str
    filename: str
    vulnerable: str
    safe: str
    params: dict[str, list[str]] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    description: str = ""


TEMPLATES: list[VulnTemplate] = [
    # ── CWE-89: SQL injection ──────────────────────────────────────────────
    VulnTemplate(
        key="sqli_flask_concat",
        cwe="CWE-89",
        language="python",
        filename="api/$module.py",
        description="User-controlled query parameter concatenated into SQL.",
        params={
            "module": ["users", "accounts", "customers"],
            "func": ["search_users", "lookup_account", "find_customer"],
            "param": ["username", "email", "account_id"],
            "table": ["users", "accounts", "customers"],
            "col": ["username", "email", "account_id"],
        },
        vulnerable='''\
import sqlite3
import logging

from flask import Blueprint, jsonify, request

log = logging.getLogger(__name__)
bp = Blueprint("$module", __name__)
DB_PATH = "data/$module.db"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@bp.route("/api/$module/search", methods=["GET"])
def $func():
    $param = request.args.get("$param", "").strip()
    if not $param:
        return jsonify({"error": "missing $param"}), 400

    conn = _connect()
    cursor = conn.cursor()
    query = "SELECT id, $col, created_at FROM $table WHERE $col = '" + $param + "'"  # @alt:CWE-89
    cursor.execute(query)  # @vuln:CWE-89
    rows = cursor.fetchall()
    conn.close()

    log.info("$func returned %d rows", len(rows))
    return jsonify([dict(row) for row in rows])
''',
        safe='''\
import sqlite3
import logging

from flask import Blueprint, jsonify, request

log = logging.getLogger(__name__)
bp = Blueprint("$module", __name__)
DB_PATH = "data/$module.db"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@bp.route("/api/$module/search", methods=["GET"])
def $func():
    $param = request.args.get("$param", "").strip()
    if not $param:
        return jsonify({"error": "missing $param"}), 400

    conn = _connect()
    cursor = conn.cursor()
    query = "SELECT id, $col, created_at FROM $table WHERE $col = ?"
    cursor.execute(query, ($param,))
    rows = cursor.fetchall()
    conn.close()

    log.info("$func returned %d rows", len(rows))
    return jsonify([dict(row) for row in rows])
''',
    ),
    VulnTemplate(
        key="sqli_fstring_multihop",
        cwe="CWE-89",
        language="python",
        filename="services/$module.py",
        description="Taint flows through two intermediate variables into an f-string query.",
        tags=["multihop"],
        params={
            "module": ["reporting", "billing", "inventory"],
            "func": ["build_report", "fetch_invoices", "list_stock"],
            "table": ["reports", "invoices", "stock_items"],
        },
        vulnerable='''\
from datetime import datetime

from django.db import connection


class ${func}_Service:
    """Aggregates $table for the admin dashboard."""

    def __init__(self, request):
        self.request = request
        self.now = datetime.utcnow()

    def _filters(self) -> dict:
        raw = self.request.GET.get("filter", "")
        return {"clause": raw, "ts": self.now}

    def $func(self):
        filters = self._filters()
        clause = filters["clause"]
        sql = f"SELECT * FROM $table WHERE status = 'active' AND {clause}"  # @alt:CWE-89
        with connection.cursor() as cursor:
            cursor.execute(sql)  # @vuln:CWE-89
            columns = [c[0] for c in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
''',
        safe='''\
from datetime import datetime

from django.db import connection

ALLOWED_STATUS = {"active", "pending", "archived"}


class ${func}_Service:
    """Aggregates $table for the admin dashboard."""

    def __init__(self, request):
        self.request = request
        self.now = datetime.utcnow()

    def _filters(self) -> dict:
        raw = self.request.GET.get("filter", "")
        return {"status": raw if raw in ALLOWED_STATUS else "active", "ts": self.now}

    def $func(self):
        filters = self._filters()
        status = filters["status"]
        sql = "SELECT * FROM $table WHERE status = %s"
        with connection.cursor() as cursor:
            cursor.execute(sql, [status])
            columns = [c[0] for c in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
''',
    ),
    # ── CWE-78: OS command injection ───────────────────────────────────────
    VulnTemplate(
        key="cmdi_os_system",
        cwe="CWE-78",
        language="python",
        filename="workers/$module.py",
        description="User-supplied value interpolated into a shell command.",
        params={
            "module": ["media", "backup", "convert"],
            "func": ["make_thumbnail", "archive_folder", "transcode"],
            "param": ["filename", "target", "clip_name"],
        },
        vulnerable='''\
import os
import logging

log = logging.getLogger(__name__)
OUTPUT_DIR = "/var/app/output"


def $func($param: str, quality: int = 85) -> str:
    """Run the external tool and return the output path."""
    output = os.path.join(OUTPUT_DIR, "${module}_out")
    cmd = "convert -quality " + str(quality) + " uploads/" + $param + " " + output  # @alt:CWE-78
    log.info("running: %s", cmd)
    exit_code = os.system(cmd)  # @vuln:CWE-78
    if exit_code != 0:
        raise RuntimeError("tool failed with code %d" % exit_code)
    return output
''',
        safe='''\
import os
import shlex
import logging
import subprocess

log = logging.getLogger(__name__)
OUTPUT_DIR = "/var/app/output"


def $func($param: str, quality: int = 85) -> str:
    """Run the external tool and return the output path."""
    output = os.path.join(OUTPUT_DIR, "${module}_out")
    safe_name = os.path.basename($param)
    cmd = ["convert", "-quality", str(quality), os.path.join("uploads", safe_name), output]
    log.info("running: %s", shlex.join(cmd))
    result = subprocess.run(cmd, shell=False, check=False)
    if result.returncode != 0:
        raise RuntimeError("tool failed with code %d" % result.returncode)
    return output
''',
    ),
    VulnTemplate(
        key="cmdi_subprocess_shell",
        cwe="CWE-78",
        language="python",
        filename="api/$module.py",
        description="subprocess with shell=True on a request-controlled string.",
        params={
            "module": ["diagnostics", "network", "ops"],
            "func": ["ping_host", "trace_route", "check_port"],
            "param": ["host", "target_ip", "endpoint"],
        },
        vulnerable='''\
import subprocess

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/$module")
TIMEOUT_SECONDS = 5


@router.get("/$func")
def $func($param: str):
    if not $param:
        raise HTTPException(status_code=400, detail="$param required")
    try:
        output = subprocess.check_output(
            "ping -c 1 " + $param, shell=True, timeout=TIMEOUT_SECONDS, text=True  # @vuln:CWE-78
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="timeout")
    return {"$param": $param, "output": output}
''',
        safe='''\
import subprocess

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/$module")
TIMEOUT_SECONDS = 5


@router.get("/$func")
def $func($param: str):
    if not $param:
        raise HTTPException(status_code=400, detail="$param required")
    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", $param], shell=False, timeout=TIMEOUT_SECONDS, text=True
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="timeout")
    return {"$param": $param, "output": output}
''',
    ),
    # ── CWE-94: code injection ─────────────────────────────────────────────
    VulnTemplate(
        key="code_injection_eval",
        cwe="CWE-94",
        language="python",
        filename="engine/$module.py",
        description="eval() on a user-provided expression.",
        params={
            "module": ["rules", "formulas", "pricing"],
            "func": ["evaluate_rule", "compute_formula", "apply_pricing"],
        },
        vulnerable='''\
import logging
from typing import Any

log = logging.getLogger(__name__)


class ${module}_Engine:
    """Evaluates customer-defined $module expressions."""

    def __init__(self, context: dict[str, Any]):
        self.context = context

    def $func(self, expression: str) -> Any:
        log.debug("evaluating %s", expression)
        if not expression.strip():
            return None
        return eval(expression, {"__builtins__": {}}, self.context)  # @vuln:CWE-94
''',
        safe='''\
import ast
import logging
import operator
from typing import Any

log = logging.getLogger(__name__)

_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}


class ${module}_Engine:
    """Evaluates customer-defined $module expressions."""

    def __init__(self, context: dict[str, Any]):
        self.context = context

    def _eval_node(self, node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self.context[node.id]
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](self._eval_node(node.left), self._eval_node(node.right))
        raise ValueError("unsupported expression")

    def $func(self, expression: str) -> Any:
        log.debug("evaluating %s", expression)
        if not expression.strip():
            return None
        return self._eval_node(ast.parse(expression, mode="eval").body)
''',
    ),
    # ── CWE-502: insecure deserialization ──────────────────────────────────
    VulnTemplate(
        key="deser_pickle",
        cwe="CWE-502",
        language="python",
        filename="cache/$module.py",
        description="pickle.loads on bytes from an external cache/request.",
        params={
            "module": ["session", "state", "jobstore"],
            "func": ["load_session", "restore_state", "read_job"],
        },
        vulnerable='''\
import base64
import pickle
import logging

import redis

log = logging.getLogger(__name__)
client = redis.Redis(host="cache", port=6379, decode_responses=False)


def $func(token: str):
    """Rehydrate the $module blob addressed by the client-supplied token."""
    raw = client.get("$module:" + token)
    if raw is None:
        return None
    decoded = base64.b64decode(raw)
    return pickle.loads(decoded)  # @vuln:CWE-502
''',
        safe='''\
import base64
import json
import logging

import redis

log = logging.getLogger(__name__)
client = redis.Redis(host="cache", port=6379, decode_responses=False)


def $func(token: str):
    """Rehydrate the $module blob addressed by the client-supplied token."""
    raw = client.get("$module:" + token)
    if raw is None:
        return None
    decoded = base64.b64decode(raw)
    return json.loads(decoded.decode("utf-8"))
''',
    ),
    VulnTemplate(
        key="deser_yaml",
        cwe="CWE-502",
        language="python",
        filename="config/$module.py",
        description="yaml.load with the unsafe default loader on uploaded content.",
        params={
            "module": ["pipeline", "deploy", "workflow"],
            "func": ["parse_pipeline", "load_deploy_spec", "read_workflow"],
        },
        vulnerable='''\
import io
import logging

import yaml

log = logging.getLogger(__name__)
MAX_BYTES = 1024 * 256


def $func(upload) -> dict:
    """Parse a user-uploaded $module definition."""
    content = upload.read(MAX_BYTES)
    if not content:
        raise ValueError("empty $module file")
    spec = yaml.load(io.BytesIO(content), Loader=yaml.Loader)  # @vuln:CWE-502
    log.info("loaded $module with %d keys", len(spec or {}))
    return spec or {}
''',
        safe='''\
import io
import logging

import yaml

log = logging.getLogger(__name__)
MAX_BYTES = 1024 * 256


def $func(upload) -> dict:
    """Parse a user-uploaded $module definition."""
    content = upload.read(MAX_BYTES)
    if not content:
        raise ValueError("empty $module file")
    spec = yaml.safe_load(io.BytesIO(content))
    log.info("loaded $module with %d keys", len(spec or {}))
    return spec or {}
''',
    ),
    # ── CWE-22: path traversal ─────────────────────────────────────────────
    VulnTemplate(
        key="path_traversal_open",
        cwe="CWE-22",
        language="python",
        filename="api/$module.py",
        description="Request-controlled path joined onto a base directory without containment check.",
        params={
            "module": ["documents", "exports", "attachments"],
            "func": ["download_document", "fetch_export", "get_attachment"],
            "param": ["doc_name", "export_id", "attachment"],
        },
        vulnerable='''\
import os

from flask import Blueprint, Response, request, abort

bp = Blueprint("$module", __name__)
STORAGE_ROOT = "/srv/app/$module"


@bp.route("/$module/download")
def $func():
    $param = request.args.get("$param", "")
    if not $param:
        abort(400)

    path = os.path.join(STORAGE_ROOT, $param)  # @alt:CWE-22
    if not os.path.exists(path):
        abort(404)
    with open(path, "rb") as fh:  # @vuln:CWE-22
        payload = fh.read()
    return Response(payload, mimetype="application/octet-stream")
''',
        safe='''\
import os

from flask import Blueprint, Response, request, abort

bp = Blueprint("$module", __name__)
STORAGE_ROOT = "/srv/app/$module"


@bp.route("/$module/download")
def $func():
    $param = request.args.get("$param", "")
    if not $param:
        abort(400)

    path = os.path.realpath(os.path.join(STORAGE_ROOT, $param))
    if not path.startswith(os.path.realpath(STORAGE_ROOT) + os.sep):
        abort(403)
    if not os.path.exists(path):
        abort(404)
    with open(path, "rb") as fh:
        payload = fh.read()
    return Response(payload, mimetype="application/octet-stream")
''',
    ),
    # ── CWE-79: XSS ────────────────────────────────────────────────────────
    VulnTemplate(
        key="xss_mark_safe",
        cwe="CWE-79",
        language="python",
        filename="views/$module.py",
        description="User input passed through mark_safe, bypassing auto-escaping.",
        params={
            "module": ["profile", "comments", "listing"],
            "func": ["render_bio", "render_comment", "render_description"],
            "field": ["bio", "body", "description"],
        },
        vulnerable='''\
from django.shortcuts import render
from django.utils.safestring import mark_safe


def $func(request, obj):
    """Render the $field block for the $module page."""
    $field = obj.$field or ""
    html = "<div class='$module-$field'>" + $field + "</div>"
    context = {
        "${field}_html": mark_safe(html),  # @vuln:CWE-79
        "owner": obj.owner_id,
    }
    return render(request, "$module/detail.html", context)
''',
        safe='''\
from django.shortcuts import render
from django.utils.html import escape, format_html


def $func(request, obj):
    """Render the $field block for the $module page."""
    $field = obj.$field or ""
    html = format_html("<div class='$module-$field'>{}</div>", escape($field))
    context = {
        "${field}_html": html,
        "owner": obj.owner_id,
    }
    return render(request, "$module/detail.html", context)
''',
    ),
    VulnTemplate(
        key="xss_innerhtml_js",
        cwe="CWE-79",
        language="javascript",
        filename="src/$module.js",
        description="Untrusted value written to innerHTML.",
        params={
            "module": ["search", "profile", "notifications"],
            "func": ["renderResults", "renderProfile", "renderAlerts"],
        },
        vulnerable='''\
const CONTAINER_ID = "$module-container";

export function $func(items) {
  const container = document.getElementById(CONTAINER_ID);
  if (!container) return;

  const query = new URLSearchParams(window.location.search).get("q") || "";
  container.innerHTML = `<h2>Results for ${query}</h2>`;  // @vuln:CWE-79

  items.forEach((item) => {
    const row = document.createElement("div");
    row.textContent = item.label;
    container.appendChild(row);
  });
}
''',
        safe='''\
const CONTAINER_ID = "$module-container";

export function $func(items) {
  const container = document.getElementById(CONTAINER_ID);
  if (!container) return;

  const query = new URLSearchParams(window.location.search).get("q") || "";
  const heading = document.createElement("h2");
  heading.textContent = `Results for ${query}`;
  container.replaceChildren(heading);

  items.forEach((item) => {
    const row = document.createElement("div");
    row.textContent = item.label;
    container.appendChild(row);
  });
}
''',
    ),
    # ── CWE-798: hardcoded credentials ─────────────────────────────────────
    VulnTemplate(
        key="hardcoded_secret",
        cwe="CWE-798",
        language="python",
        filename="clients/$module.py",
        description="Credential literal committed in source.",
        params={
            "module": ["payments", "mailer", "analytics"],
            "func": ["charge_card", "send_campaign", "push_events"],
        },
        vulnerable='''\
import requests

BASE_URL = "https://api.$module.example.com/v2"
API_KEY = "example-placeholder-for-demo-only"  # @vuln:CWE-798
TIMEOUT = 10


class ${module}_Client:
    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        self.session.headers["Authorization"] = "Bearer " + API_KEY

    def $func(self, payload: dict) -> dict:
        response = self.session.post(BASE_URL + "/$func", json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
''',
        safe='''\
import os

import requests

BASE_URL = "https://api.$module.example.com/v2"
API_KEY = os.environ["${module}_API_KEY".upper()]
TIMEOUT = 10


class ${module}_Client:
    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        self.session.headers["Authorization"] = "Bearer " + API_KEY

    def $func(self, payload: dict) -> dict:
        response = self.session.post(BASE_URL + "/$func", json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
''',
    ),
    # ── CWE-327: weak crypto for passwords ─────────────────────────────────
    VulnTemplate(
        key="weak_hash_password",
        cwe="CWE-327",
        language="python",
        filename="auth/$module.py",
        description="MD5 used to hash credentials.",
        params={
            "module": ["accounts", "identity", "users"],
            "func": ["hash_password", "store_credential", "set_password"],
        },
        vulnerable='''\
import hashlib
import os


SALT_BYTES = 16


def $func(password: str) -> tuple[str, str]:
    """Return (salt_hex, digest_hex) for storage."""
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.md5(salt + password.encode("utf-8")).hexdigest()  # @vuln:CWE-327
    return salt.hex(), digest


def verify(password: str, salt_hex: str, expected: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    return hashlib.md5(salt + password.encode("utf-8")).hexdigest() == expected
''',
        safe='''\
import hashlib
import hmac
import os


SALT_BYTES = 16
ITERATIONS = 480_000


def $func(password: str) -> tuple[str, str]:
    """Return (salt_hex, digest_hex) for storage."""
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS).hex()
    return salt.hex(), digest


def verify(password: str, salt_hex: str, expected: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS).hex()
    return hmac.compare_digest(digest, expected)
''',
    ),
    # ── CWE-330: weak randomness for security tokens ───────────────────────
    VulnTemplate(
        key="weak_random_token",
        cwe="CWE-330",
        language="python",
        filename="auth/$module.py",
        description="Predictable PRNG used to mint a security token.",
        params={
            "module": ["reset", "invites", "sessions"],
            "func": ["make_reset_token", "make_invite_code", "new_session_id"],
        },
        vulnerable='''\
import random
import string
import time

TOKEN_LENGTH = 32
ALPHABET = string.ascii_letters + string.digits


def $func(user_id: str) -> dict:
    """Mint a single-use $module token."""
    random.seed(time.time())
    token = "".join(random.choice(ALPHABET) for _ in range(TOKEN_LENGTH))  # @vuln:CWE-330
    return {"user_id": user_id, "token": token, "issued_at": time.time()}
''',
        safe='''\
import secrets
import string
import time

TOKEN_LENGTH = 32
ALPHABET = string.ascii_letters + string.digits


def $func(user_id: str) -> dict:
    """Mint a single-use $module token."""
    token = "".join(secrets.choice(ALPHABET) for _ in range(TOKEN_LENGTH))
    return {"user_id": user_id, "token": token, "issued_at": time.time()}
''',
    ),
    # ── CWE-295: TLS verification disabled ─────────────────────────────────
    VulnTemplate(
        key="tls_verify_disabled",
        cwe="CWE-295",
        language="python",
        filename="clients/$module.py",
        description="Certificate verification turned off on an outbound request.",
        params={
            "module": ["partner", "ledger", "registry"],
            "func": ["fetch_manifest", "sync_ledger", "pull_registry"],
        },
        vulnerable='''\
import logging

import requests

log = logging.getLogger(__name__)
ENDPOINT = "https://$module.internal.example.com/api/manifest"


def $func(auth_token: str) -> dict:
    headers = {"Authorization": "Bearer " + auth_token}
    response = requests.get(ENDPOINT, headers=headers, timeout=15, verify=False)  # @vuln:CWE-295
    response.raise_for_status()
    log.info("$func ok status=%s", response.status_code)
    return response.json()
''',
        safe='''\
import logging
import os

import requests

log = logging.getLogger(__name__)
ENDPOINT = "https://$module.internal.example.com/api/manifest"
CA_BUNDLE = os.environ.get("INTERNAL_CA_BUNDLE", True)


def $func(auth_token: str) -> dict:
    headers = {"Authorization": "Bearer " + auth_token}
    response = requests.get(ENDPOINT, headers=headers, timeout=15, verify=CA_BUNDLE)
    response.raise_for_status()
    log.info("$func ok status=%s", response.status_code)
    return response.json()
''',
    ),
    # ── CWE-918: SSRF ──────────────────────────────────────────────────────
    VulnTemplate(
        key="ssrf_fetch_url",
        cwe="CWE-918",
        language="python",
        filename="api/$module.py",
        description="Server fetches a fully user-controlled URL.",
        params={
            "module": ["webhooks", "importer", "preview"],
            "func": ["test_webhook", "import_feed", "preview_link"],
        },
        vulnerable='''\
import requests
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/$module")
TIMEOUT = 8


@router.post("/$func")
def $func(url: str):
    if not url.startswith("http"):
        raise HTTPException(status_code=400, detail="invalid url")
    response = requests.get(url, timeout=TIMEOUT)  # @vuln:CWE-918
    return {"status": response.status_code, "body": response.text[:2000]}
''',
        safe='''\
import ipaddress
import socket
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/$module")
TIMEOUT = 8
ALLOWED_SCHEMES = {"https"}


def _is_public(hostname: str) -> bool:
    try:
        addr = ipaddress.ip_address(socket.gethostbyname(hostname))
    except (socket.gaierror, ValueError):
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


@router.post("/$func")
def $func(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname or not _is_public(parsed.hostname):
        raise HTTPException(status_code=400, detail="invalid url")
    response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
    return {"status": response.status_code, "body": response.text[:2000]}
''',
    ),
    # ── CWE-611: XXE ───────────────────────────────────────────────────────
    VulnTemplate(
        key="xxe_lxml",
        cwe="CWE-611",
        language="python",
        filename="parsers/$module.py",
        description="XML parser configured to resolve external entities.",
        params={
            "module": ["invoices", "catalog", "feeds"],
            "func": ["parse_invoice", "parse_catalog", "parse_feed"],
        },
        vulnerable='''\
import logging

from lxml import etree

log = logging.getLogger(__name__)


def $func(xml_bytes: bytes) -> dict:
    """Parse an uploaded $module document."""
    parser = etree.XMLParser(resolve_entities=True, no_network=False)  # @vuln:CWE-611
    root = etree.fromstring(xml_bytes, parser=parser)
    log.info("parsed $module root=%s", root.tag)
    return {child.tag: child.text for child in root}
''',
        safe='''\
import logging

from lxml import etree

log = logging.getLogger(__name__)


def $func(xml_bytes: bytes) -> dict:
    """Parse an uploaded $module document."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(xml_bytes, parser=parser)
    log.info("parsed $module root=%s", root.tag)
    return {child.tag: child.text for child in root}
''',
    ),
    # ── CWE-306: missing authentication ────────────────────────────────────
    VulnTemplate(
        key="missing_auth_admin",
        cwe="CWE-306",
        language="python",
        filename="api/$module.py",
        description="State-changing admin route exposed with no auth check.",
        params={
            "module": ["admin", "internal", "ops"],
            "func": ["delete_user", "reset_tenant", "purge_cache"],
        },
        vulnerable='''\
from flask import Blueprint, jsonify, request

from app.services import ${module}_service

bp = Blueprint("$module", __name__)


@bp.route("/$module/$func", methods=["POST"])  # @alt:CWE-306
def $func():  # @vuln:CWE-306
    payload = request.get_json(silent=True) or {}
    target = payload.get("target_id")
    if not target:
        return jsonify({"error": "target_id required"}), 400
    ${module}_service.$func(target)
    return jsonify({"status": "ok", "target": target})
''',
        safe='''\
from flask import Blueprint, jsonify, request

from app.auth import admin_required
from app.services import ${module}_service

bp = Blueprint("$module", __name__)


@bp.route("/$module/$func", methods=["POST"])
@admin_required
def $func():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target_id")
    if not target:
        return jsonify({"error": "target_id required"}), 400
    ${module}_service.$func(target)
    return jsonify({"status": "ok", "target": target})
''',
    ),
    # ── CWE-209: information exposure ──────────────────────────────────────
    VulnTemplate(
        key="info_leak_traceback",
        cwe="CWE-209",
        language="python",
        filename="api/$module.py",
        description="Internal exception detail returned to the client.",
        params={
            "module": ["orders", "payments", "shipping"],
            "func": ["create_order", "capture_payment", "book_shipment"],
        },
        vulnerable='''\
import traceback

from flask import Blueprint, jsonify, request

from app.services import ${module}_service

bp = Blueprint("$module", __name__)


@bp.route("/$module", methods=["POST"])
def $func():
    try:
        return jsonify(${module}_service.$func(request.get_json()))
    except Exception as exc:
        return jsonify({"error": str(exc), "trace": traceback.format_exc()}), 500  # @vuln:CWE-209
''',
        safe='''\
import logging
import uuid

from flask import Blueprint, jsonify, request

from app.services import ${module}_service

log = logging.getLogger(__name__)
bp = Blueprint("$module", __name__)


@bp.route("/$module", methods=["POST"])
def $func():
    try:
        return jsonify(${module}_service.$func(request.get_json()))
    except Exception:
        incident = uuid.uuid4().hex
        log.exception("$func failed incident=%s", incident)
        return jsonify({"error": "internal error", "incident": incident}), 500
''',
    ),
    # ── CWE-732: permissive file permissions ───────────────────────────────
    VulnTemplate(
        key="perms_world_writable",
        cwe="CWE-732",
        language="python",
        filename="storage/$module.py",
        description="Secret material written world-readable/writable.",
        params={
            "module": ["keystore", "vault", "certs"],
            "func": ["write_key", "persist_secret", "save_cert"],
        },
        vulnerable='''\
import os

BASE_DIR = "/var/lib/app/$module"


def $func(name: str, material: bytes) -> str:
    os.makedirs(BASE_DIR, exist_ok=True)
    path = os.path.join(BASE_DIR, name)
    with open(path, "wb") as fh:
        fh.write(material)
    os.chmod(path, 0o777)  # @vuln:CWE-732
    return path
''',
        safe='''\
import os

BASE_DIR = "/var/lib/app/$module"


def $func(name: str, material: bytes) -> str:
    os.makedirs(BASE_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(BASE_DIR, name)
    with open(path, "wb") as fh:
        fh.write(material)
    os.chmod(path, 0o600)
    return path
''',
    ),
]


# ── Distractors: clean code that looks alarming ────────────────────────────
# These are where naive keyword/regex scanners generate their false positives.
# Ground truth: no findings. Flagging any of these is a measured mistake.

@dataclass
class DistractorTemplate:
    key: str
    language: str
    filename: str
    code: str
    note: str
    params: dict[str, list[str]] = field(default_factory=dict)


DISTRACTORS: list[DistractorTemplate] = [
    DistractorTemplate(
        key="md5_cache_key",
        language="python",
        filename="cache/$module.py",
        note="MD5 used as a non-security cache key, explicitly marked usedforsecurity=False.",
        params={"module": ["render", "thumbs", "pages"], "func": ["cache_key_for", "digest_of", "fingerprint"]},
        code='''\
import hashlib
import json

CACHE_VERSION = "v3"


def $func(payload: dict) -> str:
    """Content-addressed cache key. Not a security control."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.md5(canonical.encode("utf-8"), usedforsecurity=False).hexdigest()
    return CACHE_VERSION + ":" + digest
''',
    ),
    DistractorTemplate(
        key="parameterized_percent_s",
        language="python",
        filename="repo/$module.py",
        note="Looks like string formatting but %s are real SQL placeholders with a params tuple.",
        params={"module": ["orders", "users", "events"], "func": ["find_by_status", "list_recent", "count_active"]},
        code='''\
import psycopg2.extras


def $func(conn, status: str, limit: int = 100):
    """Placeholders are bound by the driver, not interpolated by Python."""
    sql = "SELECT id, name, status FROM $module WHERE status = %s ORDER BY created_at DESC LIMIT %s"
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute(sql, (status, limit))
        return [dict(row) for row in cur.fetchall()]
''',
    ),
    DistractorTemplate(
        key="subprocess_list_args",
        language="python",
        filename="ops/$module.py",
        note="subprocess with an argument list and shell=False — safe by construction.",
        params={"module": ["git", "build", "deploy"], "func": ["current_revision", "run_build", "restart_service"]},
        code='''\
import subprocess

TIMEOUT = 30


def $func(repo_path: str) -> str:
    result = subprocess.run(
        ["git", "-C", repo_path, "rev-parse", "HEAD"],
        shell=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    return result.stdout.strip()
''',
    ),
    DistractorTemplate(
        key="env_var_named_password",
        language="python",
        filename="config/$module.py",
        note="Variables named password/secret, but every value comes from the environment.",
        params={"module": ["settings", "runtime", "env"], "func": ["load_config", "build_settings", "read_env"]},
        code='''\
import os


def $func() -> dict:
    password = os.environ["DB_PASSWORD"]
    api_key = os.environ.get("PARTNER_API_KEY", "")
    secret = os.environ["SESSION_SECRET"]
    if not password or not secret:
        raise RuntimeError("missing required credentials in environment")
    return {
        "dsn": f"postgresql://app:{password}@db:5432/app",
        "api_key": api_key,
        "session_secret": secret,
    }
''',
    ),
    DistractorTemplate(
        key="literal_eval",
        language="python",
        filename="parsing/$module.py",
        note="ast.literal_eval, not eval — cannot execute code.",
        params={"module": ["params", "tuples", "records"], "func": ["parse_literal", "read_tuple", "decode_record"]},
        code='''\
import ast
import logging

log = logging.getLogger(__name__)


def $func(raw: str):
    """Parse a Python literal (dict/list/number) from configuration."""
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        log.warning("could not parse literal: %r", raw[:80])
        return None
''',
    ),
    DistractorTemplate(
        key="random_jitter",
        language="python",
        filename="net/$module.py",
        note="random used for retry jitter, which is not a security context.",
        params={"module": ["retry", "backoff", "poll"], "func": ["next_delay", "backoff_seconds", "poll_interval"]},
        code='''\
import random

BASE_DELAY = 0.5
MAX_DELAY = 30.0


def $func(attempt: int) -> float:
    """Exponential backoff with full jitter. Not security-sensitive."""
    ceiling = min(MAX_DELAY, BASE_DELAY * (2 ** attempt))
    return random.uniform(0, ceiling)
''',
    ),
    DistractorTemplate(
        key="authed_route",
        language="python",
        filename="api/$module.py",
        note="Route is protected — the auth decorator is present.",
        params={"module": ["billing", "reports", "teams"], "func": ["update_plan", "export_report", "add_member"]},
        code='''\
from flask import Blueprint, jsonify, request

from app.auth import login_required

bp = Blueprint("$module", __name__)


@bp.route("/$module/$func", methods=["POST"])
@login_required
def $func(current_user):
    payload = request.get_json(silent=True) or {}
    if not payload.get("id"):
        return jsonify({"error": "id required"}), 400
    return jsonify({"status": "ok", "actor": current_user.id})
''',
    ),
    DistractorTemplate(
        key="contained_path_join",
        language="python",
        filename="files/$module.py",
        note="Path is contained: basename plus realpath prefix check.",
        params={"module": ["uploads", "reports", "media"], "func": ["read_upload", "open_report", "load_media"]},
        code='''\
import os

ROOT = "/srv/app/$module"


def $func(name: str) -> bytes:
    safe_name = os.path.basename(name)
    path = os.path.realpath(os.path.join(ROOT, safe_name))
    if not path.startswith(os.path.realpath(ROOT) + os.sep):
        raise PermissionError("path escapes $module root")
    with open(path, "rb") as fh:
        return fh.read()
''',
    ),
    DistractorTemplate(
        key="constant_sql",
        language="python",
        filename="repo/$module.py",
        note="Query is a compile-time constant with no user input anywhere.",
        params={"module": ["metrics", "health", "stats"], "func": ["table_counts", "healthcheck", "daily_stats"]},
        code='''\
DAILY_ROLLUP_SQL = """
SELECT date_trunc('day', created_at) AS day, count(*) AS total
FROM events
WHERE created_at > now() - interval '30 days'
GROUP BY 1
ORDER BY 1 DESC
"""


def $func(conn):
    with conn.cursor() as cur:
        cur.execute(DAILY_ROLLUP_SQL)
        return [{"day": row[0].isoformat(), "total": row[1]} for row in cur.fetchall()]
''',
    ),
    DistractorTemplate(
        key="textcontent_js",
        language="javascript",
        filename="src/$module.js",
        note="Uses textContent, so user input is never parsed as HTML.",
        params={"module": ["toast", "banner", "status"], "func": ["showMessage", "renderBanner", "setStatus"]},
        code='''\
export function $func(message) {
  const host = document.getElementById("$module-host");
  if (!host) return;

  const node = document.createElement("p");
  node.className = "$module-message";
  node.textContent = message;
  host.replaceChildren(node);
}
''',
    ),
]

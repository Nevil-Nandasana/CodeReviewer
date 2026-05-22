"""
Training-only vulnerability templates.

Deliberately different frameworks and idioms from the benchmark families
(aiohttp/tornado/SQLAlchemy/Express instead of Flask/Django/FastAPI) so the
training distribution is not a carbon copy of the eval distribution. Combined
with the four benchmark families that are held out entirely, this gives two
levels of generalization evidence: unseen phrasing of a seen bug class, and
entirely unseen bug classes.

Reuses the VulnTemplate/DistractorTemplate shapes and the same @vuln/@alt marker
convention as the benchmark.
"""
from __future__ import annotations

from evaluation.benchmark.templates import DistractorTemplate, VulnTemplate

TRAIN_TEMPLATES: list[VulnTemplate] = [
    VulnTemplate(
        key="tr_sqli_sqlalchemy_text",
        cwe="CWE-89",
        language="python",
        filename="db/$module.py",
        description="Raw SQLAlchemy text() query built with .format().",
        params={
            "module": ["tenants", "assets", "leads"],
            "func": ["find_tenant", "lookup_asset", "search_leads"],
            "param": ["slug", "serial", "term"],
        },
        vulnerable='''\
from sqlalchemy import text


class $module_Repository:
    def __init__(self, session):
        self.session = session

    def $func(self, $param: str):
        stmt = text("SELECT * FROM $module WHERE name = '{}'".format($param))  # @alt:CWE-89
        return self.session.execute(stmt).fetchall()  # @vuln:CWE-89
''',
        safe='''\
from sqlalchemy import text


class $module_Repository:
    def __init__(self, session):
        self.session = session

    def $func(self, $param: str):
        stmt = text("SELECT * FROM $module WHERE name = :name")
        return self.session.execute(stmt, {"name": $param}).fetchall()
''',
    ),
    VulnTemplate(
        key="tr_sqli_aiohttp",
        cwe="CWE-89",
        language="python",
        filename="handlers/$module.py",
        description="asyncpg query interpolated from a query-string value.",
        params={
            "module": ["devices", "sensors", "sites"],
            "func": ["get_device", "get_sensor", "get_site"],
            "param": ["device_id", "sensor_id", "site_id"],
        },
        vulnerable='''\
from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/$module")
async def $func(request):
    $param = request.query.get("$param", "")
    pool = request.app["db"]
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"SELECT * FROM $module WHERE id = {$param}")  # @vuln:CWE-89
    return web.json_response([dict(r) for r in rows])
''',
        safe='''\
from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/$module")
async def $func(request):
    $param = request.query.get("$param", "")
    pool = request.app["db"]
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM $module WHERE id = $1", $param)
    return web.json_response([dict(r) for r in rows])
''',
    ),
    VulnTemplate(
        key="tr_ssti_jinja",
        cwe="CWE-94",
        language="python",
        filename="views/$module.py",
        description="Server-side template injection via render_template_string.",
        params={
            "module": ["preview", "mailer", "landing"],
            "func": ["render_preview", "render_mail", "render_landing"],
        },
        vulnerable='''\
from flask import render_template_string, request


def $func():
    template = request.form.get("template", "")
    context = {"user": request.form.get("user", "guest")}
    return render_template_string(template, **context)  # @vuln:CWE-94
''',
        safe='''\
from flask import render_template, request

ALLOWED_TEMPLATES = {"welcome", "receipt", "reminder"}


def $func():
    name = request.form.get("template", "")
    if name not in ALLOWED_TEMPLATES:
        return "unknown template", 400
    context = {"user": request.form.get("user", "guest")}
    return render_template(f"$module/{name}.html", **context)
''',
    ),
    VulnTemplate(
        key="tr_cmdi_popen",
        cwe="CWE-78",
        language="python",
        filename="tools/$module.py",
        description="os.popen invoked with a user-controlled argument.",
        params={
            "module": ["dns", "scan", "logs"],
            "func": ["resolve_name", "scan_target", "tail_log"],
            "param": ["domain", "target", "logfile"],
        },
        vulnerable='''\
import os


def $func($param: str) -> list[str]:
    handle = os.popen("dig +short " + $param)  # @vuln:CWE-78
    try:
        return [line.strip() for line in handle if line.strip()]
    finally:
        handle.close()
''',
        safe='''\
import subprocess


def $func($param: str) -> list[str]:
    result = subprocess.run(
        ["dig", "+short", $param], shell=False, capture_output=True, text=True, timeout=10
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]
''',
    ),
    VulnTemplate(
        key="tr_debug_enabled",
        cwe="CWE-209",
        language="python",
        filename="$module/app.py",
        description="Debug mode enabled on a publicly bound server.",
        params={"module": ["portal", "service", "gateway"], "func": ["create_app", "make_app", "bootstrap"]},
        vulnerable='''\
from flask import Flask


def $func():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me"
    return app


if __name__ == "__main__":
    $func().run(host="0.0.0.0", port=8000, debug=True)  # @vuln:CWE-209
''',
        safe='''\
import os

from flask import Flask


def $func():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
    return app


if __name__ == "__main__":
    $func().run(host="0.0.0.0", port=8000, debug=False)
''',
    ),
    VulnTemplate(
        key="tr_csrf_exempt",
        cwe="CWE-352",
        language="python",
        filename="views/$module.py",
        description="CSRF protection disabled on a state-changing view.",
        params={"module": ["transfer", "settings", "payouts"], "func": ["submit_transfer", "update_settings", "request_payout"]},
        vulnerable='''\
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt  # @vuln:CWE-352
def $func(request):
    amount = request.POST.get("amount")
    request.user.$module.create(amount=amount)
    return JsonResponse({"status": "ok"})
''',
        safe='''\
from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def $func(request):
    amount = request.POST.get("amount")
    request.user.$module.create(amount=amount)
    return JsonResponse({"status": "ok"})
''',
    ),
    VulnTemplate(
        key="tr_xss_react",
        cwe="CWE-79",
        language="javascript",
        filename="src/components/$module.jsx",
        description="dangerouslySetInnerHTML fed with server-provided content.",
        params={"module": ["Article", "Comment", "Bio"], "func": ["Article", "Comment", "Bio"]},
        vulnerable='''\
import React from "react";

export default function $func({ item }) {
  return (
    <div className="$module">
      <h3>{item.title}</h3>
      <div dangerouslySetInnerHTML={{ __html: item.body }} />  // @vuln:CWE-79
    </div>
  );
}
''',
        safe='''\
import React from "react";
import DOMPurify from "dompurify";

export default function $func({ item }) {
  const clean = DOMPurify.sanitize(item.body);
  return (
    <div className="$module">
      <h3>{item.title}</h3>
      <div dangerouslySetInnerHTML={{ __html: clean }} />
    </div>
  );
}
''',
    ),
    VulnTemplate(
        key="tr_sqli_express",
        cwe="CWE-89",
        language="javascript",
        filename="routes/$module.js",
        description="Template literal interpolation into a SQL query in Express.",
        params={"module": ["orders", "items", "users"], "func": ["getOrder", "getItem", "getUser"]},
        vulnerable='''\
const express = require("express");
const router = express.Router();

router.get("/$module/:id", async (req, res) => {
  const { id } = req.params;
  const sql = `SELECT * FROM $module WHERE id = ${id}`;  // @alt:CWE-89
  const [rows] = await req.db.query(sql);  // @vuln:CWE-89
  res.json(rows);
});

module.exports = router;
''',
        safe='''\
const express = require("express");
const router = express.Router();

router.get("/$module/:id", async (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM $module WHERE id = ?";
  const [rows] = await req.db.query(sql, [id]);
  res.json(rows);
});

module.exports = router;
''',
    ),
    VulnTemplate(
        key="tr_secret_aws",
        cwe="CWE-798",
        language="python",
        filename="infra/$module.py",
        description="Cloud access key committed to the repository.",
        params={"module": ["s3sync", "backups", "uploader"], "func": ["get_client", "make_session", "connect"]},
        vulnerable='''\
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # @vuln:CWE-798


def $func(region: str = "us-east-1"):
    return boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
''',
        safe='''\
import boto3


def $func(region: str = "us-east-1"):
    # Credentials resolve from the environment or the instance role.
    return boto3.client("s3", region_name=region)
''',
    ),
    VulnTemplate(
        key="tr_path_write",
        cwe="CWE-22",
        language="python",
        filename="uploads/$module.py",
        description="Uploaded filename used directly as a write path.",
        params={"module": ["avatars", "docs", "imports"], "func": ["save_avatar", "save_doc", "save_import"]},
        vulnerable='''\
import os

UPLOAD_DIR = "/srv/uploads/$module"


def $func(upload) -> str:
    destination = os.path.join(UPLOAD_DIR, upload.filename)  # @alt:CWE-22
    with open(destination, "wb") as fh:  # @vuln:CWE-22
        fh.write(upload.read())
    return destination
''',
        safe='''\
import os
import uuid

UPLOAD_DIR = "/srv/uploads/$module"


def $func(upload) -> str:
    extension = os.path.splitext(upload.filename)[1][:10]
    destination = os.path.join(UPLOAD_DIR, uuid.uuid4().hex + extension)
    with open(destination, "wb") as fh:
        fh.write(upload.read())
    return destination
''',
    ),
    VulnTemplate(
        key="tr_weak_crypto_sha1_sig",
        cwe="CWE-327",
        language="python",
        filename="security/$module.py",
        description="SHA-1 used to sign and verify a security token.",
        params={"module": ["licence", "download", "share"], "func": ["sign_token", "sign_url", "sign_share"]},
        vulnerable='''\
import hashlib
import os

SIGNING_KEY = os.environ["SIGNING_KEY"]


def $func(payload: str) -> str:
    return hashlib.sha1((SIGNING_KEY + payload).encode()).hexdigest()  # @vuln:CWE-327
''',
        safe='''\
import hashlib
import hmac
import os

SIGNING_KEY = os.environ["SIGNING_KEY"].encode()


def $func(payload: str) -> str:
    return hmac.new(SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()
''',
    ),
    VulnTemplate(
        key="tr_deser_marshal",
        cwe="CWE-502",
        language="python",
        filename="ipc/$module.py",
        description="marshal.loads applied to bytes received over a socket.",
        params={"module": ["worker", "bridge", "relay"], "func": ["read_frame", "recv_message", "decode_frame"]},
        vulnerable='''\
import marshal
import struct

HEADER = struct.Struct("!I")


def $func(sock) -> object:
    size = HEADER.unpack(sock.recv(HEADER.size))[0]
    body = sock.recv(size)
    return marshal.loads(body)  # @vuln:CWE-502
''',
        safe='''\
import json
import struct

HEADER = struct.Struct("!I")


def $func(sock) -> object:
    size = HEADER.unpack(sock.recv(HEADER.size))[0]
    body = sock.recv(size)
    return json.loads(body.decode("utf-8"))
''',
    ),
    VulnTemplate(
        key="tr_tls_unverified_context",
        cwe="CWE-295",
        language="python",
        filename="net/$module.py",
        description="urllib opened with an unverified SSL context.",
        params={"module": ["feed", "mirror", "index"], "func": ["fetch_feed", "fetch_mirror", "fetch_index"]},
        vulnerable='''\
import ssl
import urllib.request

URL = "https://$module.example.com/data.json"


def $func() -> bytes:
    context = ssl._create_unverified_context()  # @vuln:CWE-295
    with urllib.request.urlopen(URL, context=context, timeout=20) as response:
        return response.read()
''',
        safe='''\
import ssl
import urllib.request

URL = "https://$module.example.com/data.json"


def $func() -> bytes:
    context = ssl.create_default_context()
    with urllib.request.urlopen(URL, context=context, timeout=20) as response:
        return response.read()
''',
    ),
    VulnTemplate(
        key="tr_missing_auth_tornado",
        cwe="CWE-306",
        language="python",
        filename="handlers/$module.py",
        description="Tornado handler performing a privileged write with no auth check.",
        params={"module": ["config", "flags", "quota"], "func": ["ConfigHandler", "FlagHandler", "QuotaHandler"]},
        vulnerable='''\
import json

import tornado.web


class $func(tornado.web.RequestHandler):
    def post(self):  # @vuln:CWE-306
        payload = json.loads(self.request.body or b"{}")
        self.application.settings["$module"].update(payload)
        self.write({"status": "updated"})
''',
        safe='''\
import json

import tornado.web


class $func(tornado.web.RequestHandler):
    @tornado.web.authenticated
    def post(self):
        if not self.current_user.is_admin:
            raise tornado.web.HTTPError(403)
        payload = json.loads(self.request.body or b"{}")
        self.application.settings["$module"].update(payload)
        self.write({"status": "updated"})
''',
    ),
]


TRAIN_DISTRACTORS: list[DistractorTemplate] = [
    DistractorTemplate(
        key="tr_hmac_compare",
        language="python",
        filename="auth/$module.py",
        note="Correct HMAC verification with constant-time comparison.",
        params={"module": ["webhook", "callback", "signature"], "func": ["verify_signature", "check_callback", "validate"]},
        code='''\
import hmac
import hashlib
import os

SECRET = os.environ["WEBHOOK_SECRET"].encode()


def $func(body: bytes, provided: str) -> bool:
    expected = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided)
''',
    ),
    DistractorTemplate(
        key="tr_orm_query",
        language="python",
        filename="db/$module.py",
        note="ORM filter call — no raw SQL anywhere.",
        params={"module": ["accounts", "tickets", "plans"], "func": ["active_accounts", "open_tickets", "list_plans"]},
        code='''\
def $func(session, owner_id: int, limit: int = 50):
    return (
        session.query($module_Model)
        .filter($module_Model.owner_id == owner_id)
        .filter($module_Model.deleted_at.is_(None))
        .order_by($module_Model.created_at.desc())
        .limit(limit)
        .all()
    )
''',
    ),
    DistractorTemplate(
        key="tr_sha256_digest",
        language="python",
        filename="util/$module.py",
        note="SHA-256 content digest — a strong hash used appropriately.",
        params={"module": ["integrity", "manifest", "bundle"], "func": ["digest_file", "manifest_hash", "bundle_id"]},
        code='''\
import hashlib

CHUNK = 65536


def $func(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
''',
    ),
]

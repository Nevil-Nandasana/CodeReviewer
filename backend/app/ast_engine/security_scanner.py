"""
Security Scanner — OWASP Top 10 rule-based vulnerability detection.
"""
from __future__ import annotations
import re
from typing import Any
from app.ast_engine.extractor import ASTContext
from app.ast_engine.python_taint import STATE_CHANGING_METHODS


class SecurityScanner:
    DB_SINKS = {"execute", "raw", "query", "executemany", "callproc", "cursor"}
    SHELL_FUNCS = {"system", "popen", "call", "run", "Popen", "check_output"}
    DESER_PATTERNS = ["pickle.loads", "pickle.load(", "yaml.load(", "marshal.loads"]
    XSS_PATTERNS = ["mark_safe", "Markup(", "innerHTML =", "|safe", "dangerouslySetInnerHTML"]
    WEAK_CRYPTO_PATTERNS = ["hashlib.md5", "hashlib.sha1", "MD5(", "SHA1("]
    SECRET_NAME_PATTERN = re.compile(
        r'(?i)(password|secret|api_key|token|passwd|pwd|private_key)\s*=\s*["\'][^"\']{8,}["\']'
    )

    def scan(self, ast_context: ASTContext, code: str) -> list[dict[str, Any]]:
        findings: list[dict] = []
        lines = code.splitlines()
        findings.extend(self._check_sql_injection(ast_context, code, lines))
        findings.extend(self._check_hardcoded_secrets(code, lines))
        findings.extend(self._check_command_injection(ast_context, code, lines))
        findings.extend(self._check_path_traversal(ast_context, lines))
        findings.extend(self._check_xss(code, lines))
        findings.extend(self._check_weak_crypto(code, lines))
        findings.extend(self._check_insecure_deserialization(code, lines))
        findings.extend(self._check_missing_auth(ast_context))
        findings.extend(self._check_code_injection(ast_context, lines))
        findings.extend(self._check_tls_verification(lines))
        findings.extend(self._check_error_disclosure(ast_context, lines))
        return findings

    # Deliberately absent: SSRF (CWE-918), XXE (CWE-611), weak randomness
    # (CWE-330) and file permissions (CWE-732). Those four are the benchmark's
    # held-out families — they exist to measure generalisation to bug classes
    # the system was never tuned on. Writing rules for them would convert an
    # honest generalisation measurement into a memorisation score.

    CODE_EXEC_SINKS = {"eval", "exec", "compile", "render_template_string"}

    def _check_code_injection(self, ctx, lines):
        """Untrusted input reaching a dynamic-evaluation sink (CWE-94)."""
        findings = []
        for fc in ctx.function_calls:
            if fc.function not in self.CODE_EXEC_SINKS or not fc.user_input_in_args:
                continue
            findings.append({
                "vuln_type": "code_injection", "severity": "CRITICAL",
                "owasp": "A03:2021 Injection", "line": fc.line,
                "title": f"Code injection via {fc.function}()",
                "explanation": (
                    f"Untrusted input reaches '{fc.function}()', which evaluates it as code. "
                    "This is arbitrary code execution (CWE-94)."
                ),
                "suggestion": "Use ast.literal_eval() for data, or dispatch through an explicit allow-list.",
            })
        return findings

    # Disabling verification turns TLS into unauthenticated encryption: the
    # channel is still encrypted, but you no longer know who is on the far end.
    TLS_DISABLED_PATTERNS = (
        "verify=false", "_create_unverified_context", "cert_none",
        "check_hostname=false", "insecureskipverify",
    )

    def _check_tls_verification(self, lines):
        """Certificate validation switched off (CWE-295)."""
        findings = []
        for i, line in enumerate(lines, 1):
            squished = line.lower().replace(" ", "")
            if line.lstrip().startswith("#"):
                continue
            for pattern in self.TLS_DISABLED_PATTERNS:
                if pattern in squished:
                    findings.append({
                        "vuln_type": "improper_cert_validation", "severity": "HIGH",
                        "owasp": "A02:2021 Cryptographic Failures", "line": i,
                        "title": "TLS certificate verification disabled",
                        "explanation": (
                            "Certificate validation is turned off, so the connection is "
                            "encrypted but unauthenticated and open to interception (CWE-295)."
                        ),
                        "suggestion": "Leave verification enabled; pin a CA bundle if you need a private CA.",
                    })
                    break
        return findings

    # Returning an exception's text to the caller leaks stack frames, file
    # paths, driver messages and sometimes credentials from connection strings.
    _ERROR_ECHO = re.compile(
        r"(?:format_exc|print_exc|traceback\.\w+)\s*\(|"
        r"(?:jsonify|Response|HTTPException|return)\b[^\n]{0,80}?\bstr\s*\(\s*(?:e|err|exc|ex)\s*\)"
    )

    def _check_error_disclosure(self, ctx, lines):
        """Internal error detail returned to the client (CWE-209)."""
        route_spans = [(f.start_line, f.end_line) for f in ctx.functions if f.has_route_decorator]
        if not route_spans:
            return []

        findings = []
        for i, line in enumerate(lines, 1):
            if not any(start <= i <= end for start, end in route_spans):
                continue
            if not self._ERROR_ECHO.search(line):
                continue
            findings.append({
                "vuln_type": "info_disclosure", "severity": "MEDIUM",
                "owasp": "A05:2021 Security Misconfiguration", "line": i,
                "title": "Internal error detail returned to the client",
                "explanation": (
                    "The response includes exception text or a traceback, exposing internal "
                    "paths and implementation detail to an attacker (CWE-209)."
                ),
                "suggestion": "Log the exception server-side and return a generic error message.",
            })
        return findings

    def _check_sql_injection(self, ctx, code, lines):
        findings = []
        for df in ctx.data_flows:
            if df.sink in self.DB_SINKS and df.involves_concatenation:
                findings.append({
                    "vuln_type": "sql_injection", "severity": "CRITICAL",
                    "owasp": "A03:2021 Injection", "line": df.sink_line,
                    "title": "SQL Injection via string concatenation",
                    "explanation": f"Parameter '{df.source}' concatenated into SQL query at '{df.sink}()'.",
                    "suggestion": "Use parameterized queries: db.execute('SELECT * FROM t WHERE id=?', (user_id,))",
                })
        # Structural fallback: a SQL string assembled by interpolation, in a
        # function that also calls a DB sink.
        #
        # The taint engine is intra-procedural by design, so it cannot follow
        # `clause = self._filters()["clause"]` into an f-string — the
        # `sqli_fstring_multihop` family is exactly that shape and produced no
        # flow at all. Provenance is not actually required to call this a bug:
        # a parameterized query passes a *constant* string plus bound values,
        # so any interpolated SQL reaching `execute` is wrong regardless of
        # where the interpolated value came from. That is also why this does
        # not fire on the safe twins, whose SQL is a plain literal.
        sql_builds = [
            sc for sc in getattr(ctx, "string_concatenations", [])
            if sc.get("looks_like_sql") and sc.get("interpolated")
        ]
        if sql_builds:
            for fn in ctx.functions:
                built = [sc for sc in sql_builds if fn.start_line <= sc["line"] <= fn.end_line]
                if not built:
                    continue
                sinks = [
                    fc for fc in ctx.function_calls
                    if fc.function in self.DB_SINKS and fn.start_line <= fc.line <= fn.end_line
                ]
                for sink in sinks:
                    if any(abs(f["line"] - sink.line) <= 2 for f in findings):
                        continue
                    findings.append({
                        "vuln_type": "sql_injection", "severity": "CRITICAL",
                        "owasp": "A03:2021 Injection", "line": sink.line,
                        "title": "SQL Injection via interpolated query string",
                        "explanation": (
                            f"The query passed to '{sink.function}()' is built by string "
                            f"interpolation at line {built[0]['line']} rather than passed as a "
                            "bound parameter."
                        ),
                        "suggestion": "Use parameterized queries: cursor.execute(sql, [value])",
                    })
        return findings

    def _check_hardcoded_secrets(self, code, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            m = self.SECRET_NAME_PATTERN.search(line)
            if m:
                findings.append({
                    "vuln_type": "hardcoded_secret", "severity": "HIGH",
                    "owasp": "A02:2021 Cryptographic Failures", "line": i,
                    "title": f"Hardcoded credential: '{m.group(1)}'",
                    "explanation": "Secrets in source code are exposed in version control.",
                    "suggestion": "Use environment variables: os.environ.get('SECRET_KEY')",
                })
        return findings

    # An argument list with shell=False is the documented safe form: the OS gets
    # argv directly, so shell metacharacters in a value are inert.
    SAFE_EXEC_MARKERS = ("shell=false",)

    @staticmethod
    def _call_text(lines: list[str], start_line: int, max_lines: int = 8) -> str:
        """
        Source of the call starting at `start_line`, following continuations.

        Reads until parentheses balance so keyword arguments on wrapped lines
        are visible. Whitespace is stripped so `shell = False` and `shell=False`
        compare identically.
        """
        if not (0 < start_line <= len(lines)):
            return ""
        chunk: list[str] = []
        depth = 0
        for raw in lines[start_line - 1: start_line - 1 + max_lines]:
            chunk.append(raw)
            depth += raw.count("(") - raw.count(")")
            if depth <= 0 and chunk:
                break
        return "".join(chunk).lower().replace(" ", "")

    def _check_command_injection(self, ctx, code, lines):
        """
        Tainted input reaching a process-spawning call.

        Not every `subprocess.run` with a tainted argument is injectable.
        `subprocess.run(["convert", "-quality", str(q), path], shell=False)`
        passes user data as a single argv element, which is the correct fix, and
        flagging it means flagging the remediation we tell people to apply.
        We require either an explicit shell=True or a command built as a string.
        `os.system` and `os.popen` always take a string, so they always qualify.
        """
        findings = []
        always_shell = {"system", "popen"}

        for fc in ctx.function_calls:
            if fc.function not in self.SHELL_FUNCS or not fc.user_input_in_args:
                continue

            # A call's keyword arguments routinely sit on continuation lines,
            # so read the whole call, not just the line it starts on.
            call_text = self._call_text(lines, fc.line)
            uses_shell = "shell=true" in call_text
            arg_is_list = any(a.startswith("[") for a in fc.args) or "([" in call_text
            safe_form = any(m in call_text for m in self.SAFE_EXEC_MARKERS)

            if fc.function not in always_shell and not uses_shell:
                # No shell requested and the command is a list -> argv form, safe.
                if arg_is_list or safe_form:
                    continue

            findings.append({
                "vuln_type": "command_injection", "severity": "CRITICAL",
                "owasp": "A03:2021 Injection", "line": fc.line,
                "title": f"Command injection via {fc.function}()",
                "explanation": f"User input passed to '{fc.function}()'. Arbitrary shell commands possible.",
                "suggestion": "Use subprocess.run(['cmd', arg], shell=False)",
            })
        return findings

    # Canonicalise-then-verify: the standard containment check. `realpath`
    # collapses any '../', and the prefix test proves the result stayed inside
    # the allowed root. Seeing both is evidence the author handled traversal.
    _CONTAINMENT = (
        re.compile(r"(realpath|abspath|resolve)\s*\("),
        re.compile(r"\.startswith\s*\(|\bis_relative_to\s*\(|\bcommonpath\s*\("),
    )

    def _check_path_traversal(self, ctx, lines):
        """
        Tainted input reaching a file open, unless the file guards containment.

        A traversal check is a property of the enclosing function, not of the
        `open()` line, so we look for canonicalisation plus a prefix assertion
        anywhere in the source before reporting. Without this the rule fires on
        code that already applies the exact fix the suggestion recommends.
        """
        blob = "\n".join(lines)
        if all(pattern.search(blob) for pattern in self._CONTAINMENT):
            return []

        # Traversal is a claim about attacker-controlled input, and the taint
        # engine treats every function parameter as tainted. That is the right
        # default for propagation but too broad for reporting: an internal
        # helper called with a server-generated name is not an exposure. Only
        # report sinks that sit inside a request handler.
        route_spans = [
            (f.start_line, f.end_line)
            for f in ctx.functions
            if f.has_route_decorator
        ]
        if not route_spans:
            return []

        def web_reachable(line: int) -> bool:
            return any(start <= line <= end for start, end in route_spans)

        findings = []
        for fc in ctx.function_calls:
            if fc.function == "open" and fc.user_input_in_args and web_reachable(fc.line):
                findings.append({
                    "vuln_type": "path_traversal", "severity": "HIGH",
                    "owasp": "A01:2021 Broken Access Control", "line": fc.line,
                    "title": "Path traversal via unsanitized file path",
                    "explanation": "User input used as file path. Attacker can read arbitrary files with '../'.",
                    "suggestion": "Validate with os.path.realpath() and check against allowed base directory.",
                })
        return findings

    def _check_xss(self, code, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            for p in self.XSS_PATTERNS:
                if p in line:
                    findings.append({
                        "vuln_type": "xss", "severity": "HIGH",
                        "owasp": "A03:2021 Injection", "line": i,
                        "title": f"Potential XSS via {p}",
                        "explanation": f"'{p}' bypasses auto-escaping. User input here enables XSS.",
                        "suggestion": "Escape user input before marking safe. Use bleach.clean() for HTML.",
                    })
                    break
        return findings

    def _check_weak_crypto(self, code, lines):
        """
        MD5/SHA-1 used as a security primitive.

        `usedforsecurity=False` (PEP 644 / OpenSSL FIPS) is the caller stating
        outright that this digest is a cache key or a checksum, not a security
        control. MD5 is a perfectly reasonable content-addressing hash; flagging
        it there is the false positive that teaches people to ignore the tool.
        """
        findings = []
        for i, line in enumerate(lines, 1):
            if "usedforsecurity=false" in line.lower().replace(" ", ""):
                continue
            for p in self.WEAK_CRYPTO_PATTERNS:
                if p in line:
                    findings.append({
                        "vuln_type": "weak_crypto", "severity": "MEDIUM",
                        "owasp": "A02:2021 Cryptographic Failures", "line": i,
                        "title": f"Weak hash: {p.split('(')[0]}",
                        "explanation": "MD5/SHA-1 are cryptographically broken for security use.",
                        "suggestion": "Use hashlib.sha256() or bcrypt for passwords.",
                    })
                    break
        return findings

    def _check_insecure_deserialization(self, code, lines):
        findings = []
        for i, line in enumerate(lines, 1):
            for p in self.DESER_PATTERNS:
                if p in line:
                    findings.append({
                        "vuln_type": "insecure_deserialization", "severity": "CRITICAL",
                        "owasp": "A08:2021 Software and Data Integrity Failures", "line": i,
                        "title": f"Insecure deserialization: {p}",
                        "explanation": f"'{p}' on untrusted data can execute arbitrary code.",
                        "suggestion": "Use json.loads(). Never pickle untrusted data.",
                    })
                    break
        return findings

    # URL segments that mark a route as privileged or destructive.
    ADMIN_PATH_MARKERS = (
        "admin", "internal", "ops", "manage", "superuser", "sudo", "debug",
        "purge", "reset", "delete", "destroy", "revoke", "impersonate",
    )

    def _looks_administrative(self, func, ctx) -> bool:
        """True when the route's own path or handler name reads as privileged."""
        haystack = f"{func.name} {getattr(func, 'route_path', '')}".lower()
        return any(marker in haystack for marker in self.ADMIN_PATH_MARKERS)

    def _check_missing_auth(self, ctx):
        """
        Unauthenticated *state-changing* routes only.

        Flagging every route without an auth decorator is not a security rule,
        it is a census of public endpoints — search pages, health checks and
        read-only lookups are legitimately open, and on the benchmark that
        version produced 37 false positives against 9 real findings. Requiring
        a state-changing method keeps the true positives (an unauthenticated
        POST /internal/purge_cache) and drops the read-only noise.

        `route_methods` is only populated by the precise Python path. When it
        is empty we cannot tell GET from POST, so we stay quiet rather than
        guess — a missed finding beats a false alarm here.

        Second filter: the route must look administrative. An unauthenticated
        POST /payments is not by itself a defect — most applications
        authenticate in middleware rather than per-handler decorators, so
        "no decorator" is weak evidence. An unauthenticated POST
        /admin/delete_user is a different claim.

        Caveat, stated plainly: ADMIN_PATH_MARKERS is a heuristic, and it will
        miss a privileged route that does not advertise itself in its URL. The
        principled version checks whether the handler reaches a privileged
        service operation, which needs call-graph resolution across modules
        that this engine does not yet do.
        """
        findings = []
        for func in ctx.functions:
            if not func.has_route_decorator or func.has_auth_decorator:
                continue
            mutating = sorted(set(func.route_methods) & STATE_CHANGING_METHODS)
            if not mutating:
                continue
            if not self._looks_administrative(func, ctx):
                continue
            findings.append({
                "vuln_type": "missing_auth", "severity": "HIGH",
                "owasp": "A01:2021 Broken Access Control", "line": func.start_line,
                "title": f"Unauthenticated {'/'.join(mutating)} route '{func.name}'",
                "explanation": (
                    f"Route '{func.name}' accepts {', '.join(mutating)} and changes server "
                    "state, but carries no authentication decorator. Any anonymous caller "
                    "can invoke it."
                ),
                "suggestion": "Add @login_required, @jwt_required, or equivalent.",
            })
        return findings

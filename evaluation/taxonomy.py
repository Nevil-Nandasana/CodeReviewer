"""
CWE taxonomy + inference from free-text model output.

The scoring problem: ground truth is CWE-labeled, but a model returns prose like
"SQL query built with string concatenation". To score type-correctness fairly we
map predicted text onto a CWE, then compare within equivalence groups (CWE-77 and
CWE-78 are the same finding for our purposes; CWE-89 is not).

Inference order per prediction:
  1. explicit "CWE-89" mentioned anywhere in the text
  2. keyword patterns, evaluated in priority order (most specific first)
  3. OWASP category alone — too coarse to pin a CWE, so it yields None

Deliberately conservative: returning None means "untyped", and the scorer reports
both strict-type and location-only metrics so a weak taxonomy can never silently
inflate a system's score.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CweSpec:
    cwe: str
    name: str
    owasp: str
    default_severity: str
    group: str  # equivalence group for type matching
    patterns: tuple[str, ...] = ()


# Priority-ordered: earlier entries win when several patterns match.
CWE_SPECS: tuple[CweSpec, ...] = (
    CweSpec(
        "CWE-89", "SQL Injection", "A03:2021", "CRITICAL", "injection.sql",
        (r"sql\s*inject", r"\bsqli\b", r"parameteri[sz]ed quer", r"prepared statement",
         r"sql quer.{0,40}(concat|interpolat|f-string|format)"),
    ),
    CweSpec(
        "CWE-78", "OS Command Injection", "A03:2021", "CRITICAL", "injection.command",
        (r"command inject", r"shell inject", r"shell\s*=\s*true", r"arbitrary (shell )?command",
         r"os\.system", r"subprocess.{0,30}(shell|untrusted)"),
    ),
    CweSpec(
        "CWE-77", "Command Injection", "A03:2021", "CRITICAL", "injection.command", ()
    ),
    CweSpec(
        "CWE-94", "Code Injection", "A03:2021", "CRITICAL", "injection.code",
        (r"code inject", r"arbitrary code execution", r"\beval\(", r"\bexec\(",
         r"dynamic code evaluation"),
    ),
    CweSpec(
        "CWE-502", "Insecure Deserialization", "A08:2021", "CRITICAL", "deserialization",
        (r"deserializ", r"\bpickle\b", r"yaml\.load", r"\bmarshal\b", r"unsafe load"),
    ),
    CweSpec(
        "CWE-22", "Path Traversal", "A01:2021", "HIGH", "path.traversal",
        (r"path travers", r"directory travers", r"\.\./", r"arbitrary file (read|write|access)",
         r"unsanitized (file )?path"),
    ),
    CweSpec(
        "CWE-79", "Cross-site Scripting", "A03:2021", "HIGH", "xss",
        (r"\bxss\b", r"cross[-\s]site script", r"mark_safe", r"innerhtml",
         r"dangerouslysetinnerhtml", r"html (escap|sanitiz)"),
    ),
    CweSpec(
        "CWE-918", "Server-Side Request Forgery", "A10:2021", "HIGH", "ssrf",
        (r"\bssrf\b", r"server[-\s]side request forgery", r"fetch.{0,30}user[-\s]?(supplied|controlled) url"),
    ),
    CweSpec(
        "CWE-611", "XML External Entity", "A05:2021", "HIGH", "xxe",
        (r"\bxxe\b", r"xml external entit", r"external entity", r"resolve_entities"),
    ),
    CweSpec(
        "CWE-798", "Hardcoded Credentials", "A07:2021", "HIGH", "secrets.hardcoded",
        (r"hard[-\s]?coded (credential|secret|password|api[_\s]?key|token)",
         r"(secret|credential|password|api[_\s]?key).{0,30}(in|committed to) (source|code|version control)",
         r"embedded credential"),
    ),
    CweSpec(
        "CWE-306", "Missing Authentication", "A01:2021", "HIGH", "authz.missing",
        (r"missing auth", r"no authentication", r"unauthenticated (access|endpoint|route)",
         r"without (an )?auth", r"lacks? (an )?auth", r"broken access control",
         r"missing (authorization|permission) check"),
    ),
    CweSpec(
        "CWE-862", "Missing Authorization", "A01:2021", "HIGH", "authz.missing", ()
    ),
    CweSpec(
        "CWE-295", "Improper Certificate Validation", "A02:2021", "HIGH", "tls.verify",
        (r"verify\s*=\s*false", r"certificate (validation|verification)",
         r"disabl\w+ (ssl|tls|certificate)", r"insecureskipverify"),
    ),
    CweSpec(
        "CWE-327", "Broken or Risky Crypto", "A02:2021", "MEDIUM", "crypto.weak",
        (r"\bmd5\b", r"\bsha-?1\b", r"weak (hash|crypto|cipher|algorithm)",
         r"broken (hash|crypto|cipher)", r"\bdes\b", r"\becb\b mode", r"insecure hash"),
    ),
    CweSpec(
        "CWE-328", "Weak Hash", "A02:2021", "MEDIUM", "crypto.weak", ()
    ),
    CweSpec(
        "CWE-330", "Insufficiently Random Values", "A02:2021", "MEDIUM", "random.weak",
        (r"insecure random", r"predictable (random|token|value)", r"not cryptographically secure",
         r"random\.(random|choice|randint)", r"use (the )?secrets module", r"weak (prng|random)"),
    ),
    CweSpec(
        "CWE-319", "Cleartext Transmission", "A02:2021", "MEDIUM", "transport.cleartext",
        (r"cleartext", r"plaintext transmission", r"unencrypted (connection|transmission|channel)",
         r"\bhttp://", r"should use https"),
    ),
    CweSpec(
        "CWE-352", "Cross-Site Request Forgery", "A01:2021", "HIGH", "csrf",
        (r"\bcsrf\b", r"cross[-\s]site request forgery", r"csrf_exempt"),
    ),
    CweSpec(
        "CWE-732", "Incorrect Permission Assignment", "A05:2021", "MEDIUM", "permissions",
        (r"world[-\s]writable", r"0o?777", r"overly permissive (file )?permission", r"\bchmod\b"),
    ),
    CweSpec(
        "CWE-209", "Information Exposure Through Error Message", "A05:2021", "MEDIUM", "info.leak",
        (r"stack trace", r"traceback.{0,30}(user|response|client)", r"debug\s*=\s*true",
         r"information (disclosure|exposure|leak)", r"leaks? internal"),
    ),
    CweSpec(
        "CWE-1333", "Inefficient Regular Expression Complexity", "A05:2021", "MEDIUM", "redos",
        (r"\bredos\b", r"catastrophic backtrack", r"regular expression denial", r"regex denial"),
    ),
)

BY_CWE: dict[str, CweSpec] = {s.cwe: s for s in CWE_SPECS}

_EXPLICIT_CWE = re.compile(r"cwe[-\s_]?(\d{1,4})", re.IGNORECASE)
_COMPILED: tuple[tuple[CweSpec, re.Pattern[str]], ...] = tuple(
    (spec, re.compile(pat, re.IGNORECASE)) for spec in CWE_SPECS for pat in spec.patterns
)


def group_of(cwe: str | None) -> str | None:
    """Equivalence group for a CWE id, or None if unknown."""
    if not cwe:
        return None
    spec = BY_CWE.get(cwe.upper())
    return spec.group if spec else cwe.upper()


def default_severity(cwe: str) -> str:
    spec = BY_CWE.get(cwe.upper())
    return spec.default_severity if spec else "MEDIUM"


def infer_cwe(*text_parts: str | None) -> str | None:
    """
    Map free-text model output onto a CWE id. Returns None when nothing matches,
    which the scorer treats as 'untyped' rather than 'wrong'.
    """
    text = " ".join(p for p in text_parts if p).strip()
    if not text:
        return None

    m = _EXPLICIT_CWE.search(text)
    if m:
        candidate = f"CWE-{int(m.group(1))}"
        if candidate in BY_CWE:
            return candidate

    for spec, pattern in _COMPILED:
        if pattern.search(text):
            return spec.cwe
    return None


def types_match(gt_cwe: str, pred_cwe: str | None, untyped_counts_as_match: bool = False) -> bool:
    """
    Compare a ground-truth CWE to an inferred one via equivalence groups.

    untyped_counts_as_match=True is the lenient mode used for location-only
    metrics, where we only care that the system flagged the right line.
    """
    if pred_cwe is None:
        return untyped_counts_as_match
    return group_of(gt_cwe) == group_of(pred_cwe)


def annotate(pred) -> None:
    """Attach an inferred CWE to a PredictedFinding in place."""
    if pred.cwe is None:
        pred.cwe = infer_cwe(pred.title, pred.explanation, pred.owasp, pred.suggestion)

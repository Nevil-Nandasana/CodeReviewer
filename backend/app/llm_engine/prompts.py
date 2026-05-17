"""
Versioned prompts.

Every result record stores the prompt version it was produced with, so a score
can always be traced back to the exact instructions that produced it. Comparing
v1 vs v2 on the same model is itself an ablation row.

v1 — the prompt the production pipeline shipped with (mirrors app/llm_engine).
v2 — adds an explicit "report nothing if nothing is wrong" instruction, a line
     numbering convention, and severity definitions. v1 never tells the model it
     is allowed to return an empty list, which is a plausible driver of
     false positives on clean code; v2 lets us measure whether that is true.
"""
from __future__ import annotations

SCHEMA = (
    '{"comments": [{"line": <int>, "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", '
    '"category": "security|bug|quality|style", "title": "<short title>", '
    '"explanation": "<why this is a problem>", "suggestion": "<corrected code>", '
    '"owasp": "<OWASP category or null>"}]}'
)

V1_SYSTEM = (
    "You are an expert code reviewer specializing in Python security and best practices. "
    "Review the code change and identify bugs, security vulnerabilities, and quality issues. "
    "For each issue respond with valid JSON only: " + SCHEMA
)

V2_SYSTEM = f"""You are a senior application-security reviewer. You review code changes and report only defects you can justify from the code shown.

Respond with valid JSON only, matching this schema exactly:
{SCHEMA}

Rules:
1. `line` is the 1-based line number in the file as presented to you. Point at the line where the defect occurs, not the surrounding block.
2. Report a finding only when the code as written is exploitable or incorrect. Code that already applies the correct mitigation (parameterized queries, argument lists instead of shells, path containment checks, escaping, safe loaders, verified TLS) is NOT a finding.
3. If the code has no defects, return {{"comments": []}}. An empty list is the correct answer for correct code, and a false alarm is worse than silence.
4. Severity: CRITICAL = remote code execution or full data compromise; HIGH = auth bypass, data exposure, or injection with limited blast radius; MEDIUM = weakened security control; LOW = minor robustness issue; INFO = style.
5. Set `owasp` for security findings (e.g. "A03:2021 Injection") and name the CWE in the explanation when you are confident of it.

No markdown, no preamble, JSON only."""

SYSTEM_PROMPTS = {"v1": V1_SYSTEM, "v2": V2_SYSTEM}


def build_messages(
    code: str,
    filename: str,
    language: str = "python",
    pre_flags: list[dict] | None = None,
    version: str = "v2",
) -> list[dict[str, str]]:
    """
    Build chat messages for one review.

    Code is presented with explicit line numbers. Asking a model to count lines
    in a raw blob is a needless source of localization error, and every serious
    review tool numbers the lines it shows.
    """
    numbered = "\n".join(
        f"{i:4d} | {line}" for i, line in enumerate(code.splitlines(), start=1)
    )
    parts = [
        f"Review this {language} file: {filename}\n",
        f"<code>\n{numbered}\n</code>\n",
    ]

    if pre_flags:
        flag_lines = "\n".join(
            f"- line {f.get('line')}: {f.get('title')} ({f.get('owasp') or f.get('vuln_type')})"
            for f in pre_flags
        )
        parts.append(
            "\n<static_analysis_findings>\n"
            f"{flag_lines}\n"
            "</static_analysis_findings>\n"
            "These come from a rule-based scanner and may contain false positives. "
            "Confirm each one against the code: include it with a full explanation if it is real, "
            "and omit it if the code is actually safe.\n"
        )

    parts.append("\nRespond with JSON only.")
    return [
        {"role": "system", "content": SYSTEM_PROMPTS[version]},
        {"role": "user", "content": "".join(parts)},
    ]

"""
Interprocedural-lite taint analysis for Python, built on CPython's own `ast`.

Why a second parser when the engine already uses tree-sitter: tree-sitter is
error-tolerant, which is what you want for diff fragments that do not parse, but
its CST makes precise dataflow awkward. CPython's `ast` gives exact expression
structure, so taint propagation through assignments, f-strings and subscripts is
straightforward and correct. The extractor tries this analyzer first for Python
and falls back to the tree-sitter/regex path when the fragment does not parse,
which keeps diff tolerance without giving up precision on whole files.

What it fixes: the previous implementation asked whether a parameter name
appeared as a substring of the call arguments. That found
`execute("..." + user_id)` and nothing else, so the realistic pattern

    name = request.GET["name"]        # source
    query = "SELECT ... " + name      # propagation through concatenation
    cursor.execute(query)             # sink

produced no finding at all, and it also matched a parameter named `id` against
an argument named `identity`. This tracks taint through intermediate variables
and remembers whether the value passed through string building on the way, which
is what separates SQL injection from a parameterized query.

Scope: single function, flow-insensitive within a function (a fixpoint over the
statement list), no cross-function propagation. Loops and branches are handled by
iterating to a fixpoint rather than by path-sensitive analysis, so it
over-approximates rather than missing flows.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

# Attribute chains that introduce untrusted data.
#
# Both spellings of every accessor are needed. Flask exposes the request body as
# the property `request.json` *and* the method `request.get_json()`, and a
# prefix match on "request.json" does not match "request.get_json" — so listing
# only the property silently misses one of the most common patterns in the
# framework. That gap made `subprocess.run("rm -rf " + request.get_json()["x"],
# shell=True)` scan clean while the identical `request.args` version was caught.
SOURCE_ATTRIBUTES: set[str] = {
    "request.args", "request.form", "request.json", "request.data", "request.values",
    "request.files", "request.cookies", "request.headers", "request.query",
    "request.query_params", "request.body", "request.GET", "request.POST",
    "request.params", "req.query", "req.body", "req.params", "self.request",
    # Method-call accessors for the same data.
    "request.get_json", "request.get_data", "request.getlist",
    "req.get_json", "req.get_data",
}

# Calls whose return value is untrusted.
SOURCE_CALLS: set[str] = {"input", "getvalue", "recv", "read"}

# Calls that neutralize taint.
SANITIZERS: set[str] = {
    "int", "float", "bool", "len", "hash", "id",
    "quote", "escape", "clean", "secure_filename", "literal_eval",
    "basename", "uuid4", "token_urlsafe", "token_hex",
}

# Calls that pass taint through from their arguments.
PASSTHROUGH_CALLS: set[str] = {
    "str", "strip", "lower", "upper", "lstrip", "rstrip", "replace", "join",
    "format", "encode", "decode", "get", "split", "title", "capitalize",
}

DB_SINKS: set[str] = {"execute", "executemany", "executescript", "raw", "query", "fetch", "fetchval", "fetchrow", "callproc", "text"}
SHELL_SINKS: set[str] = {"system", "popen", "call", "run", "Popen", "check_output", "check_call", "spawn"}
FILE_SINKS: set[str] = {"open", "remove", "unlink", "rmtree", "makedirs", "mkdir"}
CODE_SINKS: set[str] = {"eval", "exec", "compile", "literal_eval_unsafe", "render_template_string"}
DESERIALIZE_SINKS: set[str] = {"loads", "load"}
NETWORK_SINKS: set[str] = {"get", "post", "put", "delete", "head", "request", "urlopen"}

ALL_SINKS = DB_SINKS | SHELL_SINKS | FILE_SINKS | CODE_SINKS | DESERIALIZE_SINKS | NETWORK_SINKS

ROUTE_DECORATOR_SUFFIXES = {"route", "get", "post", "put", "delete", "patch", "head", "options"}
AUTH_DECORATOR_NAMES = {
    "login_required", "auth_required", "requires_auth", "jwt_required",
    "token_required", "permission_required", "authentication_required",
    "admin_required", "authenticated", "staff_member_required",
    "permission_classes", "requires_scope",
}


@dataclass
class TaintValue:
    """Taint state for one name: where it came from and how it got here."""

    source: str
    path: list[str] = field(default_factory=list)
    via_concat: bool = False

    def extend(self, name: str, concat: bool) -> "TaintValue":
        return TaintValue(
            source=self.source,
            path=[*self.path, name],
            via_concat=self.via_concat or concat,
        )


def _dotted_name(node: ast.AST) -> str:
    """Best-effort dotted name for a Name/Attribute/Call chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return _dotted_name(node)


# Methods that change server state. A public GET endpoint is an ordinary design
# choice; a public POST that mutates something is the finding.
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _route_methods(decorator_list: list[ast.expr]) -> list[str]:
    """
    HTTP methods a route decorator responds to, upper-cased.

    Handles both conventions:
      @app.post("/x")                  -> ["POST"]     (method in the name)
      @bp.route("/x", methods=["POST"]) -> ["POST"]     (method in a kwarg)
      @bp.route("/x")                  -> ["GET"]      (Flask's default)

    Returns [] for functions that carry no route decorator at all, which lets
    callers distinguish "not a route" from "a route that only serves GET".
    """
    methods: list[str] = []

    for dec in decorator_list:
        name = _decorator_name(dec)
        suffix = name.rsplit(".", 1)[-1]
        if suffix not in ROUTE_DECORATOR_SUFFIXES:
            continue

        if suffix != "route":  # @app.post / @router.delete style
            methods.append(suffix.upper())
            continue

        explicit: list[str] = []
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg != "methods":
                    continue
                if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    explicit.extend(
                        el.value.upper()
                        for el in kw.value.elts
                        if isinstance(el, ast.Constant) and isinstance(el.value, str)
                    )
        # Flask defaults an un-annotated @route to GET only.
        methods.extend(explicit or ["GET"])

    return sorted(set(methods))


def _route_path(decorator_list: list[ast.expr]) -> str:
    """The URL a route decorator registers, or '' when there isn't one."""
    for dec in decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        if _decorator_name(dec).rsplit(".", 1)[-1] not in ROUTE_DECORATOR_SUFFIXES:
            continue
        for arg in dec.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
    return ""


class FunctionTaint:
    """Taint propagation within a single function body."""

    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef, treat_params_as_tainted: bool = True):
        self.func = func
        self.state: dict[str, TaintValue] = {}
        self.flows: list[dict[str, Any]] = []
        self.tainted_calls: list[dict[str, Any]] = []
        self.concat_lines: list[dict[str, Any]] = []

        if treat_params_as_tainted:
            for arg in [*func.args.args, *func.args.posonlyargs, *func.args.kwonlyargs]:
                if arg.arg not in ("self", "cls"):
                    self.state[arg.arg] = TaintValue(source=arg.arg, path=[arg.arg])

    # ── expression taint ────────────────────────────────────────────────
    def taint_of(self, node: ast.AST | None) -> TaintValue | None:
        if node is None:
            return None

        if isinstance(node, ast.Name):
            return self.state.get(node.id)

        if isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            if any(dotted.startswith(src) or dotted == src for src in SOURCE_ATTRIBUTES):
                return TaintValue(source=dotted, path=[dotted])
            return self.taint_of(node.value)

        if isinstance(node, ast.Subscript):
            return self.taint_of(node.value)

        if isinstance(node, ast.Starred):
            return self.taint_of(node.value)

        if isinstance(node, ast.Call):
            return self._taint_of_call(node)

        if isinstance(node, ast.BinOp):
            left, right = self.taint_of(node.left), self.taint_of(node.right)
            hit = left or right
            if hit:
                # `+` on strings and `%` formatting both build a string from
                # untrusted input, which is the signal that separates injection
                # from a bound parameter.
                concat = isinstance(node.op, (ast.Add, ast.Mod))
                return hit.extend("<concat>", concat)
            return None

        if isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    hit = self.taint_of(value.value)
                    if hit:
                        return hit.extend("<fstring>", True)
            return None

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts:
                hit = self.taint_of(element)
                if hit:
                    return hit
            return None

        if isinstance(node, ast.Dict):
            for value in [*node.keys, *node.values]:
                hit = self.taint_of(value)
                if hit:
                    return hit
            return None

        if isinstance(node, (ast.BoolOp, ast.Compare, ast.IfExp)):
            for child in ast.iter_child_nodes(node):
                hit = self.taint_of(child)
                if hit:
                    return hit
            return None

        return None

    def _taint_of_call(self, node: ast.Call) -> TaintValue | None:
        dotted = _dotted_name(node.func)
        last = dotted.rsplit(".", 1)[-1]

        if last in SANITIZERS:
            return None

        # request.args.get("x") and friends
        if any(dotted.startswith(src) for src in SOURCE_ATTRIBUTES):
            return TaintValue(source=dotted, path=[dotted])
        if last in SOURCE_CALLS and any(
            _dotted_name(node.func).startswith(src) for src in SOURCE_ATTRIBUTES
        ):
            return TaintValue(source=dotted, path=[dotted])
        if dotted in SOURCE_CALLS or last == "input":
            return TaintValue(source=dotted, path=[dotted])

        # Taint flows through the receiver: tainted.strip() stays tainted.
        receiver = self.taint_of(node.func.value) if isinstance(node.func, ast.Attribute) else None
        if receiver and last in PASSTHROUGH_CALLS:
            concat = last == "format"
            return receiver.extend(f"{last}()", concat)

        for arg in [*node.args, *[kw.value for kw in node.keywords]]:
            hit = self.taint_of(arg)
            if hit:
                if last in PASSTHROUGH_CALLS or last in ("join", "format"):
                    return hit.extend(f"{last}()", last == "format")
                # Unknown callee: assume it launders rather than sanitizes, but
                # do not mark it as string-building.
                return hit.extend(f"{last}()", False)
        return receiver

    # ── statement walk ──────────────────────────────────────────────────
    def _assign(self, targets: list[ast.expr], value: ast.expr) -> None:
        taint = self.taint_of(value)
        for target in targets:
            if isinstance(target, ast.Name):
                if taint:
                    self.state[target.id] = taint.extend(target.id, False)
                else:
                    self.state.pop(target.id, None)  # reassignment kills taint
            elif isinstance(target, (ast.Tuple, ast.List)):
                for element in target.elts:
                    if isinstance(element, ast.Name) and taint:
                        self.state[element.id] = taint.extend(element.id, False)

    def _record_sinks(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        last = dotted.rsplit(".", 1)[-1]

        args = [*node.args, *[kw.value for kw in node.keywords]]
        hits = [t for t in (self.taint_of(a) for a in args) if t]
        arg_names = [_dotted_name(a) or "<expr>" for a in node.args]

        self.tainted_calls.append(
            {
                "function": last,
                "dotted": dotted,
                "line": node.lineno,
                "args": arg_names,
                "user_input_in_args": bool(hits),
            }
        )

        if not hits or last not in ALL_SINKS:
            return

        worst = max(hits, key=lambda t: (t.via_concat, len(t.path)))
        self.flows.append(
            {
                "source": worst.source,
                "sink": last,
                "sink_line": node.lineno,
                "path": worst.path,
                "involves_concatenation": worst.via_concat,
            }
        )

    def run(self) -> None:
        # Two passes reach a fixpoint for the loop/branch shapes that appear in
        # review-sized functions without needing a full worklist algorithm.
        for _ in range(2):
            for node in ast.walk(self.func):
                if isinstance(node, ast.Assign):
                    self._assign(node.targets, node.value)
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                    self._assign([node.target], node.value)
                elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                    self._assign([node.optional_vars], node.context_expr)
                elif isinstance(node, ast.For):
                    self._assign([node.target], node.iter)

        seen_lines: set[tuple[int, str]] = set()
        for node in ast.walk(self.func):
            if isinstance(node, ast.Call):
                key = (node.lineno, _dotted_name(node.func))
                if key in seen_lines:
                    continue
                seen_lines.add(key)
                self._record_sinks(node)

            # Both `"..." + x` / `"..." % x` and f-strings build a string from
            # parts. An f-string is the more common modern spelling of the SQL
            # injection bug, so it has to be recorded the same way — the plain
            # literal a parameterized query uses is a Constant, not a JoinedStr,
            # which is what keeps the safe form out of this list.
            is_binop = isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
            is_fstring = isinstance(node, ast.JoinedStr) and any(
                isinstance(v, ast.FormattedValue) for v in node.values
            )
            if is_binop or is_fstring:
                text_parts = [
                    n.value for n in ast.walk(node)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)
                ]
                blob = " ".join(text_parts).upper()
                self.concat_lines.append(
                    {
                        "line": node.lineno,
                        "involves_param": bool(self.taint_of(node)),
                        "interpolated": True,
                        "looks_like_sql": any(
                            kw in blob for kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "WHERE")
                        ),
                    }
                )


def _complexity(func: ast.AST) -> int:
    branch_types = (
        ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
        ast.With, ast.AsyncWith, ast.BoolOp, ast.IfExp, ast.Assert,
    )
    return 1 + sum(1 for node in ast.walk(func) if isinstance(node, branch_types))


def analyze_python(code: str) -> dict[str, Any] | None:
    """
    Analyze a whole Python source file.

    Returns None when the code does not parse, so the caller can fall back to the
    error-tolerant tree-sitter path.
    """
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return None

    functions: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    concats: list[dict[str, Any]] = []
    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(f"import {alias.name}" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.extend(f"from {module} import {alias.name}" for alias in node.names)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        decorators = [_decorator_name(d) for d in node.decorator_list]
        has_route = any(
            d == "route" or ("." in d and d.rsplit(".", 1)[-1] in ROUTE_DECORATOR_SUFFIXES)
            for d in decorators
        )
        has_auth = any(d.rsplit(".", 1)[-1] in AUTH_DECORATOR_NAMES for d in decorators)
        route_methods = _route_methods(node.decorator_list)

        end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
        params = [
            a.arg
            for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if a.arg not in ("self", "cls")
        ]

        functions.append(
            {
                "name": node.name,
                "start_line": node.lineno,
                "end_line": end_line,
                "params": params,
                "has_route_decorator": has_route,
                "has_auth_decorator": has_auth,
                "route_methods": route_methods,
                "route_path": _route_path(node.decorator_list),
                "complexity": _complexity(node),
                "length": end_line - node.lineno + 1,
                "decorators": decorators,
            }
        )

        analyzer = FunctionTaint(node)
        analyzer.run()
        flows.extend(analyzer.flows)
        calls.extend(analyzer.tainted_calls)
        concats.extend(analyzer.concat_lines)

    return {
        "functions": functions,
        "data_flows": flows,
        "function_calls": calls,
        "string_concatenations": concats,
        "imports": imports,
    }

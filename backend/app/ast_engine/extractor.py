"""
AST Extractor — Tree-sitter based code analysis.
Extracts function signatures, call graphs, data flows, and variable scopes
from Python, JavaScript/TypeScript, and Java source code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

try:
    import tree_sitter_python as tspython
    import tree_sitter_javascript as tsjavascript
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Node, Parser

    PY_LANGUAGE = Language(tspython.language(), "python")
    JS_LANGUAGE = Language(tsjavascript.language(), "javascript")
    JAVA_LANGUAGE = Language(tsjava.language(), "java")
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    PY_LANGUAGE = JS_LANGUAGE = JAVA_LANGUAGE = None


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    params: list[str] = field(default_factory=list)
    has_route_decorator: bool = False
    has_auth_decorator: bool = False
    complexity: int = 1
    length: int = 0
    # HTTP methods the route serves, upper-cased. Empty when not a route, or
    # when the extractor could not determine them (regex/tree-sitter paths).
    route_methods: list[str] = field(default_factory=list)
    # The URL the route registers, e.g. "/admin/delete_user".
    route_path: str = ""


@dataclass
class DataFlow:
    source: str
    sink: str
    path: list[str] = field(default_factory=list)
    sink_line: int = 0
    involves_concatenation: bool = False


@dataclass
class FunctionCall:
    function: str
    line: int
    args: list[str] = field(default_factory=list)
    user_input_in_args: bool = False


@dataclass
class ASTContext:
    language: str
    functions: list[FunctionInfo] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    function_calls: list[FunctionCall] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    string_concatenations: list[dict] = field(default_factory=list)
    modified_functions: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "functions": [
                {
                    "name": f.name,
                    "lines": f"{f.start_line}-{f.end_line}",
                    "params": f.params,
                    "complexity": f.complexity,
                    "has_route_decorator": f.has_route_decorator,
                    "has_auth_decorator": f.has_auth_decorator,
                }
                for f in self.functions
            ],
            "data_flows": [
                {
                    "source": df.source,
                    "sink": df.sink,
                    "path": df.path,
                    "sink_line": df.sink_line,
                    "involves_concatenation": df.involves_concatenation,
                }
                for df in self.data_flows
            ],
            "function_calls": [
                {
                    "function": fc.function,
                    "line": fc.line,
                    "user_input_in_args": fc.user_input_in_args,
                }
                for fc in self.function_calls
            ],
            "imports": self.imports,
            "string_concatenations": self.string_concatenations,
            "modified_functions": self.modified_functions,
        }


class ASTExtractor:
    """
    Tree-sitter based AST extractor.
    Falls back to regex-based extraction if tree-sitter is unavailable.
    """

    # Auth decorators that signal a route is protected
    AUTH_DECORATORS = {
        "login_required", "auth_required", "requires_auth",
        "jwt_required", "token_required", "permission_required",
        "authentication_required", "admin_required",
    }

    # Route decorators
    ROUTE_DECORATORS = {
        "route", "get", "post", "put", "delete", "patch",
        "app.route", "router.get", "router.post", "router.put",
        "router.delete", "router.patch",
    }

    # Database sink function names
    DB_SINKS = {"execute", "raw", "query", "cursor", "executemany", "callproc"}

    def __init__(self):
        self._parsers: dict[str, Any] = {}
        if TREE_SITTER_AVAILABLE:
            self._parsers["python"] = self._make_parser(PY_LANGUAGE)
            self._parsers["javascript"] = self._make_parser(JS_LANGUAGE)
            self._parsers["typescript"] = self._make_parser(JS_LANGUAGE)
            self._parsers["java"] = self._make_parser(JAVA_LANGUAGE)

    def _make_parser(self, language) -> Any:
        p = Parser()
        p.set_language(language)
        return p

    def extract(self, code: str, language: str) -> ASTContext:
        """
        Extract AST context from source code.
        Returns an ASTContext with functions, data flows, calls, imports.

        Python takes the CPython-`ast` taint path first. Tree-sitter is error
        tolerant, which is what diff fragments need, but its CST makes precise
        dataflow awkward — the substring heuristic it falls back on only sees
        `execute("..." + user_id)` and misses taint that reaches a sink through
        an intermediate variable or an f-string. When the fragment does not
        parse, we drop back to tree-sitter and keep the tolerance.
        """
        lang = language.lower()
        ctx = ASTContext(language=lang)

        if lang == "python":
            precise = self._extract_with_python_ast(code, ctx)
            if precise is not None:
                return precise

        if TREE_SITTER_AVAILABLE and lang in self._parsers:
            try:
                return self._extract_with_treesitter(code, lang, ctx)
            except Exception:
                pass  # fall through to regex

        return self._extract_with_regex(code, lang, ctx)

    def _extract_with_python_ast(self, code: str, ctx: ASTContext) -> ASTContext | None:
        """Precise Python path. Returns None when the source does not parse."""
        from app.ast_engine.python_taint import analyze_python

        try:
            data = analyze_python(code)
        except Exception:
            return None
        if data is None:
            return None

        for f in data["functions"]:
            ctx.functions.append(
                FunctionInfo(
                    name=f["name"],
                    start_line=f["start_line"],
                    end_line=f["end_line"],
                    params=f["params"],
                    has_route_decorator=f["has_route_decorator"],
                    has_auth_decorator=f["has_auth_decorator"],
                    complexity=f["complexity"],
                    length=f["length"],
                    route_methods=f.get("route_methods", []),
                    route_path=f.get("route_path", ""),
                )
            )
            ctx.modified_functions.append(
                {
                    "name": f["name"],
                    "lines": f"{f['start_line']}-{f['end_line']}",
                    "complexity": f["complexity"],
                    "data_flows": [],
                }
            )

        for df in data["data_flows"]:
            ctx.data_flows.append(
                DataFlow(
                    source=df["source"],
                    sink=df["sink"],
                    path=df["path"],
                    sink_line=df["sink_line"],
                    involves_concatenation=df["involves_concatenation"],
                )
            )

        for fc in data["function_calls"]:
            ctx.function_calls.append(
                FunctionCall(
                    function=fc["function"],
                    line=fc["line"],
                    args=fc["args"],
                    user_input_in_args=fc["user_input_in_args"],
                )
            )

        ctx.imports = data["imports"]
        ctx.string_concatenations = data["string_concatenations"]
        return ctx

    def _extract_with_treesitter(self, code: str, lang: str, ctx: ASTContext) -> ASTContext:
        """Tree-sitter based extraction for Python."""
        parser = self._parsers[lang]
        tree = parser.parse(code.encode())
        root = tree.root_node

        if lang == "python":
            self._walk_python(root, code, ctx)
        else:
            self._extract_with_regex(code, lang, ctx)

        return ctx

    def _walk_python(self, node: "Node", code: str, ctx: ASTContext) -> None:
        """Walk Python AST tree and extract relevant constructs."""

        def get_text(n) -> str:
            return code[n.start_byte:n.end_byte]

        def walk(node, current_func: FunctionInfo | None = None):
            if node.type == "import_statement" or node.type == "import_from_statement":
                ctx.imports.append(get_text(node).strip())

            elif node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                func_name = get_text(name_node) if name_node else "unknown"

                params_node = node.child_by_field_name("parameters")
                params = []
                if params_node:
                    for child in params_node.children:
                        if child.type in ("identifier", "typed_parameter"):
                            params.append(get_text(child).split(":")[0].strip())

                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1

                func_info = FunctionInfo(
                    name=func_name,
                    start_line=start_line,
                    end_line=end_line,
                    params=[p for p in params if p not in ("self", "cls")],
                    length=end_line - start_line + 1,
                )

                # Check decorators
                parent = node.parent
                if parent and parent.type == "decorated_definition":
                    for sibling in parent.children:
                        if sibling.type == "decorator":
                            dec_text = get_text(sibling).lstrip("@").split("(")[0].lower()
                            if dec_text in self.ROUTE_DECORATORS:
                                func_info.has_route_decorator = True
                            if dec_text in self.AUTH_DECORATORS:
                                func_info.has_auth_decorator = True

                # Count complexity (branches)
                body = node.child_by_field_name("body")
                if body:
                    func_info.complexity = 1 + self._count_branches(body, get_text)

                ctx.functions.append(func_info)
                ctx.modified_functions.append({
                    "name": func_name,
                    "lines": f"{start_line}-{end_line}",
                    "complexity": func_info.complexity,
                    "data_flows": [],
                })

                # Walk function body with this func as context
                for child in node.children:
                    walk(child, func_info)
                return

            elif node.type == "call" and current_func:
                func_node = node.child_by_field_name("function")
                if func_node:
                    call_name = get_text(func_node)
                    call_line = node.start_point[0] + 1
                    args_node = node.child_by_field_name("arguments")
                    args_text = get_text(args_node) if args_node else ""

                    # Check if user input (function param) flows into call
                    user_input = any(p in args_text for p in current_func.params)

                    fc = FunctionCall(
                        function=call_name.split(".")[-1],
                        line=call_line,
                        user_input_in_args=user_input,
                    )
                    ctx.function_calls.append(fc)

                    # Detect data flows to DB sinks
                    sink_name = call_name.split(".")[-1]
                    if sink_name in self.DB_SINKS and user_input:
                        for param in current_func.params:
                            if param in args_text:
                                df = DataFlow(
                                    source=param,
                                    sink=sink_name,
                                    sink_line=call_line,
                                    involves_concatenation="+" in args_text or "%" in args_text,
                                )
                                ctx.data_flows.append(df)
                                if ctx.modified_functions:
                                    ctx.modified_functions[-1]["data_flows"].append({
                                        "source": param,
                                        "sink": sink_name,
                                        "path": [param],
                                    })

            elif node.type == "binary_operator" and current_func:
                op_text = get_text(node)
                if "+" in op_text:
                    line = node.start_point[0] + 1
                    involves_param = any(p in op_text for p in current_func.params)
                    looks_like_sql = any(
                        kw in op_text.upper()
                        for kw in ["SELECT", "INSERT", "UPDATE", "DELETE", "WHERE"]
                    )
                    ctx.string_concatenations.append({
                        "line": line,
                        "involves_param": involves_param,
                        "looks_like_sql": looks_like_sql,
                    })

            for child in node.children:
                walk(child, current_func)

        walk(node)

    def _count_branches(self, node, get_text) -> int:
        """Count cyclomatic complexity branches in a function body."""
        count = 0
        branch_types = {
            "if_statement", "elif_clause", "for_statement",
            "while_statement", "except_clause", "with_statement",
            "boolean_operator",
        }
        for child in node.children:
            if child.type in branch_types:
                count += 1
            count += self._count_branches(child, get_text)
        return count

    def _extract_with_regex(self, code: str, lang: str, ctx: ASTContext) -> ASTContext:
        """Regex-based fallback extractor — works for any language."""
        lines = code.splitlines()

        if lang == "python":
            # Extract function definitions
            func_pattern = re.compile(r"^(\s*)def\s+(\w+)\s*\(([^)]*)\)\s*:", re.MULTILINE)
            for match in func_pattern.finditer(code):
                indent, name, params_str = match.groups()
                start_line = code[:match.start()].count("\n") + 1
                params = [p.strip().split(":")[0].split("=")[0].strip()
                          for p in params_str.split(",") if p.strip()]
                params = [p for p in params if p not in ("self", "cls", "")]
                ctx.functions.append(FunctionInfo(
                    name=name, start_line=start_line, end_line=start_line + 10,
                    params=params
                ))

            # Extract imports
            import_pattern = re.compile(r"^(?:import|from)\s+\S+.*$", re.MULTILINE)
            ctx.imports = import_pattern.findall(code)

            # Extract function calls
            call_pattern = re.compile(r"(\w+(?:\.\w+)*)\s*\(")
            for i, line in enumerate(lines, 1):
                for match in call_pattern.finditer(line):
                    call_name = match.group(1)
                    ctx.function_calls.append(FunctionCall(
                        function=call_name.split(".")[-1], line=i
                    ))

        return ctx

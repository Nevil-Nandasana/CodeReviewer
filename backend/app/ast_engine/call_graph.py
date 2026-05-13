"""Function call graph builder."""
from __future__ import annotations
from app.ast_engine.extractor import ASTContext


class CallGraphBuilder:
    def build(self, ast_context: ASTContext) -> dict:
        graph: dict[str, list[str]] = {}
        func_names = {f.name for f in ast_context.functions}
        for func in ast_context.functions:
            calls = [fc.function for fc in ast_context.function_calls
                     if fc.line >= func.start_line and fc.line <= func.end_line
                     and fc.function in func_names]
            graph[func.name] = calls
        return graph

"""Guards that ServerContext's deleted globals (managers, merge_conditions) never come back."""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_ROOT = REPO_ROOT / "iam_validator" / "mcp"

_DELETED_CLASS_NAMES = frozenset({"SessionConfigManager", "CustomInstructionsManager"})
_DELETED_FUNCTION_NAMES = frozenset({"merge_conditions"})

# lru_cache/cache turn a function into the process-wide memoized singleton context.py deleted.
_MEMOIZING_DECORATOR_NAMES = frozenset({"lru_cache", "cache"})


def _mcp_source_files() -> list[Path]:
    return sorted(MCP_ROOT.rglob("*.py"))


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _decorator_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


class TestDeletedGlobalStateNeverReturns:
    def test_no_deleted_manager_class_is_defined_anywhere_in_mcp(self):
        hits: dict[str, set[str]] = {}
        for path in _mcp_source_files():
            names = {
                node.name
                for node in ast.walk(_parse(path))
                if isinstance(node, ast.ClassDef) and node.name in _DELETED_CLASS_NAMES
            }
            if names:
                hits[str(path.relative_to(REPO_ROOT))] = names
        assert not hits, f"deleted global-state manager class(es) reintroduced: {hits}"

    def test_no_deleted_manager_class_is_importable_from_mcp(self):
        import importlib

        for module_path in ("iam_validator.mcp.context", "iam_validator.mcp.build"):
            module = importlib.import_module(module_path)
            present = _DELETED_CLASS_NAMES & set(vars(module))
            assert not present, f"{module_path} re-exposes deleted class(es): {present}"

    def test_merge_conditions_helper_never_returns(self):
        hits: dict[str, set[str]] = {}
        for path in _mcp_source_files():
            names = {
                node.name
                for node in ast.walk(_parse(path))
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in _DELETED_FUNCTION_NAMES
            }
            if names:
                hits[str(path.relative_to(REPO_ROOT))] = names
        assert not hits, f"deleted helper function(s) reintroduced: {hits}"


class TestNoModuleLevelMutableState:
    def test_no_global_statement_anywhere_in_mcp(self):
        """ServerContext exists so no function needs a `global` statement to mutate state across calls."""
        hits: dict[str, list[str]] = {}
        for path in _mcp_source_files():
            names = [name for node in ast.walk(_parse(path)) if isinstance(node, ast.Global) for name in node.names]
            if names:
                hits[str(path.relative_to(REPO_ROOT))] = names
        assert not hits, f"`global` statement(s) found -- state belongs on ServerContext instead: {hits}"

    def test_no_memoizing_decorator_anywhere_in_mcp(self):
        hits: dict[str, set[str]] = {}
        for path in _mcp_source_files():
            names: set[str] = set()
            for node in ast.walk(_parse(path)):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                for decorator in node.decorator_list:
                    name = _decorator_name(decorator)
                    if name in _MEMOIZING_DECORATOR_NAMES:
                        names.add(node.name)
            if names:
                hits[str(path.relative_to(REPO_ROOT))] = names
        assert not hits, f"memoizing decorator on function(s) -- reintroduces a process-wide singleton: {hits}"

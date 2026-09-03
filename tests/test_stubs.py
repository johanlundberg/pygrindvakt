"""The .pyi stubs must describe exactly the runtime surface.

For every submodule, the set of public names in the stub equals the set of
public names at runtime, and for every class the stub's methods/properties are a
superset-equal of the runtime's. Keeps stubs from drifting when the Rust side
changes.
"""

import ast
import importlib
import pathlib

import pytest

import pygrindvakt

STUB_DIR = pathlib.Path(pygrindvakt.__file__).parent
SUBMODULES = [
    "client", "discovery", "dpop", "federation", "http", "jwt", "keys", "mac",
    "metadata", "pkce", "provider", "request", "rp", "tokens", "util",
]
# Names that exist only in stubs (typing helpers) and are not runtime objects.
STUB_ONLY_SUFFIX = "Protocol"


def _stub_names(tree):
    names = set()
    classes = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            if not node.name.startswith("_"):
                names.add(node.name)
            if isinstance(node, ast.ClassDef):
                members = set()
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and not item.name.startswith("_"):
                        members.add(item.name)
                    elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        members.add(item.target.id)
                    elif isinstance(item, ast.Assign):
                        for t in item.targets:
                            if isinstance(t, ast.Name):
                                members.add(t.id)
                classes[node.name] = members
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and not t.id.startswith("_"):
                    names.add(t.id)
    return names, classes


def _runtime_names(mod):
    return {n for n in dir(mod) if not n.startswith("_")}


@pytest.mark.parametrize("name", SUBMODULES)
def test_stub_matches_runtime(name):
    stub = STUB_DIR / f"{name}.pyi"
    assert stub.exists(), f"missing stub {stub}"
    tree = ast.parse(stub.read_text(), str(stub))
    stub_names, stub_classes = _stub_names(tree)
    mod = importlib.import_module(f"pygrindvakt.{name}")
    runtime = _runtime_names(mod)
    stub_public = {n for n in stub_names if not n.endswith(STUB_ONLY_SUFFIX)}
    missing_in_stub = runtime - stub_public
    missing_at_runtime = stub_public - runtime
    assert not missing_in_stub, f"{name}: runtime names absent from stub: {sorted(missing_in_stub)}"
    assert not missing_at_runtime, f"{name}: stub names absent at runtime: {sorted(missing_at_runtime)}"
    for cls_name, members in stub_classes.items():
        if cls_name.endswith(STUB_ONLY_SUFFIX):
            continue
        cls = getattr(mod, cls_name)
        rt_members = {m for m in dir(cls) if not m.startswith("_")}
        assert rt_members == members, (
            f"{name}.{cls_name}: stub {sorted(members ^ rt_members)} differs "
            f"(stub-only: {sorted(members - rt_members)}, runtime-only: {sorted(rt_members - members)})"
        )


def test_top_level_stub_lists_all_submodules_and_exceptions():
    tree = ast.parse((STUB_DIR / "__init__.pyi").read_text())
    names = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            names.update(a.asname or a.name for a in node.names)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    for n in pygrindvakt.__all__:
        assert n in names, f"__init__.pyi lacks {n}"

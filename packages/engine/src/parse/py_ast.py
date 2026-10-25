"""
Python AST extraction for CodeLens.

Reads a source file path from argv and prints the same facts the TypeScript
parser produces, as JSON on stdout. Runs with -I (isolated) from the caller so
nothing is imported from the analysed project's directory.
"""
import ast
import json
import sys

MAX_TEXT = 1200
MAX_ARG = 200


def dotted(node):
    """Flatten a.b.c into a dotted string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return f"{dotted(node.func)}()"
    if isinstance(node, ast.Subscript):
        return f"{dotted(node.value)}[]"
    return ""


def root_object(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return root_object(node.value)
    return None


class Extractor(ast.NodeVisitor):
    def __init__(self, src, lines):
        self.src = src
        self.lines = lines
        self.imports = []
        self.exports = []
        self.symbols = []
        self.calls = []
        self.member_accesses = []
        self.object_literals = []
        self.env_vars = set()
        self.string_literals = []
        self.has_try = False
        self.symbol_stack = []
        self.loop_depth = 0

    def seg(self, node):
        try:
            return ast.get_source_segment(self.src, node) or ""
        except Exception:
            return ""

    def current_symbol(self):
        return self.symbol_stack[-1] if self.symbol_stack else None

    # ---- imports ----
    def visit_Import(self, node):
        for a in node.names:
            self.imports.append({
                "specifier": a.name, "names": [a.asname or a.name],
                "line": node.lineno, "external": True,
            })
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        # level > 0 is a relative import.
        spec = ("." * node.level) + mod if node.level else mod
        self.imports.append({
            "specifier": spec,
            "names": [a.asname or a.name for a in node.names],
            "line": node.lineno,
            "external": node.level == 0,
        })
        self.generic_visit(node)

    # ---- symbols ----
    def _function(self, node, is_async):
        decorators = [("@" + self.seg(d)) if not self.seg(d).startswith("@") else self.seg(d)
                      for d in node.decorator_list]
        parent = None
        for frame in reversed(self.symbol_stack):
            parent = frame
            break
        self.symbols.append({
            "name": node.name,
            "kind": "method" if parent and parent[0].isupper() else "function",
            "exported": not node.name.startswith("_"),
            "async": is_async,
            "startLine": node.lineno,
            "endLine": getattr(node, "end_lineno", node.lineno),
            "params": [a.arg for a in node.args.args],
            "text": self.seg(node)[:MAX_TEXT],
            "parent": parent,
            "decorators": decorators,
        })
        if not node.name.startswith("_"):
            self.exports.append(node.name)
        self.symbol_stack.append(node.name)
        self.generic_visit(node)
        self.symbol_stack.pop()

    def visit_FunctionDef(self, node):
        self._function(node, False)

    def visit_AsyncFunctionDef(self, node):
        self._function(node, True)

    def visit_ClassDef(self, node):
        self.symbols.append({
            "name": node.name, "kind": "class", "exported": not node.name.startswith("_"),
            "async": False, "startLine": node.lineno,
            "endLine": getattr(node, "end_lineno", node.lineno),
            "params": [], "text": self.seg(node)[:MAX_TEXT],
            "decorators": ["@" + self.seg(d) for d in node.decorator_list],
        })
        self.exports.append(node.name)
        # Class attribute names are the declared shape (ORM models, Pydantic).
        keys = []
        for item in node.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                keys.append(item.target.id)
            elif isinstance(item, ast.Assign):
                for t in item.targets:
                    if isinstance(t, ast.Name):
                        keys.append(t.id)
        if keys:
            self.object_literals.append({"keys": keys, "line": node.lineno, "inSymbol": node.name})
        self.symbol_stack.append(node.name)
        self.generic_visit(node)
        self.symbol_stack.pop()

    # ---- calls ----
    def visit_Call(self, node):
        callee = dotted(node.func)
        args = [self.seg(a)[:MAX_ARG] for a in node.args]
        self.calls.append({
            "callee": callee, "args": args, "line": node.lineno,
            "inSymbol": self.current_symbol(),
            "insideLoop": self.loop_depth > 0,
            "awaited": False,
        })
        # os.environ.get("X") / os.getenv("X")
        if callee in ("os.environ.get", "os.getenv", "environ.get", "getenv"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.env_vars.add(node.args[0].value)
        self.generic_visit(node)

    def visit_Await(self, node):
        if isinstance(node.value, ast.Call):
            callee = dotted(node.value.func)
            self.calls.append({
                "callee": callee,
                "args": [self.seg(a)[:MAX_ARG] for a in node.value.args],
                "line": node.lineno, "inSymbol": self.current_symbol(),
                "insideLoop": self.loop_depth > 0, "awaited": True,
            })
            for a in node.value.args:
                self.generic_visit(a)
            return
        self.generic_visit(node)

    # ---- loops ----
    def _loop(self, node):
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1

    visit_For = _loop
    visit_AsyncFor = _loop
    visit_While = _loop
    visit_ListComp = _loop
    visit_GeneratorExp = _loop

    # ---- misc ----
    def visit_Try(self, node):
        self.has_try = True
        self.generic_visit(node)

    def visit_Attribute(self, node):
        chain = dotted(node)
        if chain.startswith("os.environ."):
            self.env_vars.add(chain[len("os.environ."):])
        root = root_object(node.value)
        if root:
            self.member_accesses.append({
                "object": root, "property": node.attr, "line": node.lineno,
                "inSymbol": self.current_symbol(),
            })
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if dotted(node.value) == "os.environ" and isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, str):
                self.env_vars.add(node.slice.value)
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and 0 < len(node.value) < 500:
            self.string_literals.append({"value": node.value, "line": node.lineno})
        self.generic_visit(node)

    def visit_Dict(self, node):
        keys = [k.value for k in node.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        if keys:
            self.object_literals.append({
                "keys": keys, "line": node.lineno, "inSymbol": self.current_symbol(),
            })
        self.generic_visit(node)


def main():
    path = sys.argv[1]
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        src = fh.read()
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        print(json.dumps({"parsed": False, "parseError": f"SyntaxError: {e}"}))
        return
    ex = Extractor(src, src.count("\n") + 1)
    ex.visit(tree)
    print(json.dumps({
        "parsed": True,
        "imports": ex.imports,
        "exports": sorted(set(ex.exports)),
        "symbols": ex.symbols,
        "calls": ex.calls,
        "jsx": [],
        "memberAccesses": ex.member_accesses,
        "objectLiterals": ex.object_literals,
        "envVars": sorted(ex.env_vars),
        "stringLiterals": ex.string_literals,
        "hasTryCatch": ex.has_try,
        "lines": src.count("\n") + 1,
    }))


if __name__ == "__main__":
    main()

"""AST-based usage analysis."""

from __future__ import annotations

import ast
from pathlib import Path

from ephemeral_scope.domain.enums import UsageKind
from ephemeral_scope.domain.models import ApiUsage, ProjectManifest


class AstUsageAnalyzer:
    """AST nodes to find imports, calls, attributes, and inheritance"""

    def analyze(self, manifest: ProjectManifest, package_name: str) -> list[ApiUsage]:
        """Collect every usage of ``package_name`` across the projects Python files"""
        usages: list[ApiUsage] = []
        for file in manifest.source_files + manifest.test_files:
            usages.extend(self.analyze_file(file, package_name))
        return usages

    def analyze_file(self, file: Path, package_name: str) -> list[ApiUsage]:
        """Collect usages of ``package_name`` in a single file.

        files that cant be parsed are skipped
        """
        try:
            tree = ast.parse(Path(file).read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):
            return []

        visitor = _UsageVisitor(package_name=package_name, file=Path(file))
        visitor.visit(tree)
        return visitor.usages


class _UsageVisitor(ast.NodeVisitor):
    """Resolves dotted references back to the target package as it walks a module"""

    def __init__(self, package_name: str, file: Path) -> None:
        self.package_name = package_name
        self.file = file
        self.usages: list[ApiUsage] = []
        # Local name is fully qualified name inside the target package
        self._aliases: dict[str, str] = {}
        # Variable name is qualified name of the package symbol it was built from
        self._instances: dict[str, str] = {}
        # Nodes already reported as a call target or base class.
        self._consumed: set[int] = set()

    # imports

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if not _in_package(alias.name, self.package_name):
                continue
            bound = alias.asname or alias.name.split(".")[0]
            self._aliases[bound] = alias.name if alias.asname else bound
            self._record(
                symbol=alias.name,
                node=node,
                usage_kind=UsageKind.IMPORT,
                import_alias=alias.asname,
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Relative imports always point inside the project
        if node.level or node.module is None:
            self.generic_visit(node)
            return
        if not _in_package(node.module, self.package_name):
            self.generic_visit(node)
            return

        for alias in node.names:
            if alias.name == "*":
                continue
            qualified = f"{node.module}.{alias.name}"
            self._aliases[alias.asname or alias.name] = qualified
            self._record(
                symbol=qualified,
                node=node,
                usage_kind=UsageKind.IMPORT,
                import_alias=alias.asname,
            )
        self.generic_visit(node)

    # calls

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        if dotted is not None:
            self._consumed.add(id(node.func))
            root, _, rest = dotted.partition(".")

            if root in self._instances and rest:
                # Calling a method on an object created from the package.
                self._record(
                    symbol=f"{self._instances[root]}.{rest}",
                    node=node,
                    usage_kind=UsageKind.METHOD_CALL,
                    import_alias=None,
                )
            else:
                qualified = self._resolve(dotted)
                if qualified is not None:
                    kind = (
                        UsageKind.CLASS_REFERENCE
                        if _looks_like_class(qualified)
                        else UsageKind.FUNCTION_CALL
                    )
                    self._record(
                        symbol=qualified,
                        node=node,
                        usage_kind=kind,
                        import_alias=root if root in self._aliases else None,
                    )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # `session = requests.Session()` so later `session.get(...)`
        # can be attributed to the package
        if isinstance(node.value, ast.Call):
            dotted = _dotted_name(node.value.func)
            qualified = self._resolve(dotted) if dotted else None
            if qualified is not None:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._instances[target.id] = qualified
        self.generic_visit(node)

    # inheritance

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for base in node.bases:
            dotted = _dotted_name(base)
            qualified = self._resolve(dotted) if dotted else None
            if qualified is not None:
                self._consumed.add(id(base))
                self._record(
                    symbol=qualified,
                    node=base,
                    usage_kind=UsageKind.INHERITANCE,
                    import_alias=None,
                )
        self.generic_visit(node)

    # bare class references 

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._maybe_class_reference(node)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self._maybe_class_reference(node)
        self.generic_visit(node)

    def _maybe_class_reference(self, node: ast.expr) -> None:
        if id(node) in self._consumed:
            return
        dotted = _dotted_name(node)
        qualified = self._resolve(dotted) if dotted else None
        if qualified is None or not _looks_like_class(qualified):
            return
        self._consumed.add(id(node))
        self._record(
            symbol=qualified,
            node=node,
            usage_kind=UsageKind.CLASS_REFERENCE,
            import_alias=None,
        )

    # helpers 

    def _resolve(self, dotted: str | None) -> str | None:
        """Map a dotted source expression onto a qualified package symbol."""
        if not dotted:
            return None
        parts = dotted.split(".")
        # Longest alias prefix wins
        for size in range(len(parts), 0, -1):
            prefix = ".".join(parts[:size])
            if prefix in self._aliases:
                target = self._aliases[prefix]
                suffix = parts[size:]
                return ".".join([target, *suffix]) if suffix else target
        return None

    def _record(
        self,
        symbol: str,
        node: ast.AST,
        usage_kind: UsageKind,
        import_alias: str | None,
    ) -> None:
        self.usages.append(
            ApiUsage(
                package_name=self.package_name,
                symbol=symbol,
                file=self.file,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                usage_kind=usage_kind,
                import_alias=import_alias,
            )
        )


def _dotted_name(node: ast.expr) -> str | None:
    """``a.b.c`` attribute chains into a dotted string"""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _in_package(module: str, package_name: str) -> bool:
    """True when ``module`` is the package itself or one of its submodules."""
    return module == package_name or module.startswith(f"{package_name}.")


def _looks_like_class(qualified: str) -> bool:
    last = qualified.rsplit(".", 1)[-1]
    return bool(last) and last[0].isupper()

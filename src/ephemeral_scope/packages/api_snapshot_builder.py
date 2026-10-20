"""API snapshot construction."""

from __future__ import annotations

from pathlib import Path

import griffe

from ephemeral_scope.domain.enums import ApiSymbolKind
from ephemeral_scope.domain.models import ApiSnapshot, ApiSymbol
from ephemeral_scope.packages.pypi_client import PyPIClient

_PARAM_PREFIX = {
    griffe.ParameterKind.var_positional: "*",
    griffe.ParameterKind.var_keyword: "**",
}


class ApiSnapshotBuilder:
    """Builds a public API snapshot for each version using Griffe"""

    def __init__(self, pypi_client: PyPIClient | None = None) -> None:
        self.pypi_client = pypi_client or PyPIClient()

    def build(self, package_name: str, version: str) -> ApiSnapshot:
        """Download a release from PyPI and snapshot its public APIx"""
        source_dir = self.pypi_client.download_source(package_name, version)
        return self.build_from_path(package_name, version, source_dir)

    def build_from_path(
        self, package_name: str, version: str, source_dir: Path
    ) -> ApiSnapshot:
        """Snapshot a package that is already present on disk"""
        search_paths = _search_paths(package_name, Path(source_dir))
        module = griffe.load(package_name, search_paths=search_paths)

        symbols: list[ApiSymbol] = []
        _collect(module, symbols, seen=set())
        return ApiSnapshot(
            package_name=package_name,
            version=version,
            symbols=tuple(sorted(symbols, key=lambda s: s.qualified_name)),
        )


def _search_paths(package_name: str, source_dir: Path) -> list[str]:
    """Locate the directory that directly contains the importable package."""
    candidates = [source_dir, source_dir / "src"]
    for candidate in candidates:
        if (candidate / package_name / "__init__.py").is_file():
            return [str(candidate)]
        if (candidate / f"{package_name}.py").is_file():
            return [str(candidate)]
    return [str(p) for p in candidates if p.is_dir()]


def _collect(obj: object, symbols: list[ApiSymbol], seen: set[str]) -> None:
    """Walk a Griffe object tree recording every public symbol once"""
    kind = _symbol_kind(obj)
    path = getattr(obj, "path", None)

    if kind is not None and path is not None and path not in seen:
        seen.add(path)
        symbols.append(
            ApiSymbol(
                qualified_name=path,
                symbol_kind=kind,
                signature=_signature(obj, drop_receiver=kind is ApiSymbolKind.CLASS),
                return_type=_return_type(obj),
            )
        )

    for member in getattr(obj, "members", {}).values():
        # Aliases re-export other modules' symbols; following them would
        # duplicate entries and can fail to resolve for partial downloads.
        if isinstance(member, griffe.Alias):
            continue
        if not getattr(member, "is_public", False):
            continue
        _collect(member, symbols, seen)


def _symbol_kind(obj: object) -> ApiSymbolKind | None:
    kind = getattr(getattr(obj, "kind", None), "value", None)
    if kind == "module":
        return ApiSymbolKind.MODULE
    if kind == "class":
        return ApiSymbolKind.CLASS
    if kind == "attribute":
        return ApiSymbolKind.ATTRIBUTE
    if kind == "function":
        parent_kind = getattr(getattr(obj, "parent", None), "kind", None)
        if getattr(parent_kind, "value", None) == "class":
            return ApiSymbolKind.METHOD
        return ApiSymbolKind.FUNCTION
    return None


def _signature(obj: object, drop_receiver: bool = False) -> str | None:
    """Render a callable's parameters as `name(a, b=1, *, c=None)`"""
    parameters = getattr(obj, "parameters", None)
    if parameters is None:
        return None

    parameters = list(parameters)
    if drop_receiver and parameters and parameters[0].name in ("self", "cls"):
        parameters = parameters[1:]

    kinds = griffe.ParameterKind
    variadic = (kinds.var_positional, kinds.var_keyword)
    rendered: list[str] = []
    pending_slash = False
    star_emitted = False

    for param in parameters:
        kind = param.kind

        if kind == kinds.positional_only:
            pending_slash = True
        elif pending_slash:
            rendered.append("/")
            pending_slash = False

        # Keyword only parameters need a preceding `*` unless `*args` already provides the separator
        if kind == kinds.keyword_only and not star_emitted:
            rendered.append("*")
            star_emitted = True
        elif kind == kinds.var_positional:
            star_emitted = True

        text = f"{_PARAM_PREFIX.get(kind, '')}{param.name}"
        if param.annotation is not None:
            text += f": {param.annotation}"
        if param.default is not None and kind not in variadic:
            text += f" = {param.default}" if param.annotation else f"={param.default}"
        rendered.append(text)

    if pending_slash:
        rendered.append("/")

    return f"{getattr(obj, 'name', '')}({', '.join(rendered)})"


def _return_type(obj: object) -> str | None:
    returns = getattr(obj, "returns", None)
    return str(returns) if returns is not None else None

"""API diff between two snapshots."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ephemeral_scope.domain.enums import ChangeType
from ephemeral_scope.domain.models import ApiChange, ApiSnapshot, ApiSymbol


@dataclass(frozen=True, slots=True)
class _Param:
    """One parameter recovered from a rendered signature string"""

    name: str
    kind: str
    default: str | None

    @property
    def is_required(self) -> bool:
        return self.default is None and self.kind not in {"vararg", "kwarg"}


class ApiComparator:
    """Finds removed objects, signature changes, moved symbols, and changed defaults"""

    def compare(self, old: ApiSnapshot, new: ApiSnapshot) -> list[ApiChange]:
        """Diff two snapshots of the same package at different versions."""
        old_symbols = {s.qualified_name: s for s in old.symbols}
        new_symbols = {s.qualified_name: s for s in new.symbols}

        removed = set(old_symbols) - set(new_symbols)
        added = set(new_symbols) - set(old_symbols)

        changes: list[ApiChange] = []

        moved_from, moved_to = self._detect_moves(
            {name: old_symbols[name] for name in removed},
            {name: new_symbols[name] for name in added},
            changes,
        )

        for name in sorted(removed - moved_from):
            changes.append(
                ApiChange(
                    symbol=name,
                    change_type=ChangeType.REMOVED,
                    old_signature=old_symbols[name].signature,
                    details=f"{old_symbols[name].symbol_kind} no longer exists",
                )
            )

        for name in sorted(added - moved_to):
            changes.append(
                ApiChange(
                    symbol=name,
                    change_type=ChangeType.ADDED,
                    new_signature=new_symbols[name].signature,
                    details=f"new {new_symbols[name].symbol_kind}",
                )
            )

        for name in sorted(set(old_symbols) & set(new_symbols)):
            changes.extend(self._compare_symbol(old_symbols[name], new_symbols[name]))

        return changes

    def _detect_moves(
        self,
        removed: dict[str, ApiSymbol],
        added: dict[str, ApiSymbol],
        changes: list[ApiChange],
    ) -> tuple[set[str], set[str]]:
        """Pair a disappearance with a reappearance of the same leaf name"""
        available: dict[tuple[str, str], list[str]] = {}
        for name, symbol in added.items():
            key = (name.rsplit(".", 1)[-1], str(symbol.symbol_kind))
            available.setdefault(key, []).append(name)

        moved_from: set[str] = set()
        moved_to: set[str] = set()

        for old_name in sorted(removed):
            symbol = removed[old_name]
            key = (old_name.rsplit(".", 1)[-1], str(symbol.symbol_kind))
            candidates = available.get(key)
            if not candidates:
                continue
            new_name = sorted(candidates)[0]
            candidates.remove(new_name)

            moved_from.add(old_name)
            moved_to.add(new_name)
            changes.append(
                ApiChange(
                    symbol=old_name,
                    change_type=ChangeType.MOVED,
                    old_signature=symbol.signature,
                    new_signature=added[new_name].signature,
                    details=f"moved to {new_name}",
                )
            )

        return moved_from, moved_to

    def _compare_symbol(self, old: ApiSymbol, new: ApiSymbol) -> list[ApiChange]:
        changes: list[ApiChange] = []

        if old.return_type != new.return_type:
            changes.append(
                ApiChange(
                    symbol=new.qualified_name,
                    change_type=ChangeType.RETURN_TYPE_CHANGED,
                    old_signature=old.signature,
                    new_signature=new.signature,
                    details=f"{old.return_type or 'untyped'} -> {new.return_type or 'untyped'}",
                )
            )

        if old.signature == new.signature:
            return changes

        changes.append(
            ApiChange(
                symbol=new.qualified_name,
                change_type=ChangeType.SIGNATURE_CHANGED,
                old_signature=old.signature,
                new_signature=new.signature,
            )
        )
        changes.extend(self._compare_parameters(old, new))
        return changes

    def _compare_parameters(self, old: ApiSymbol, new: ApiSymbol) -> list[ApiChange]:
        """Report the specific parameter edits behind a signature change."""
        old_params = _parse_parameters(old.signature)
        new_params = _parse_parameters(new.signature)
        if old_params is None or new_params is None:
            return []

        old_by_name = {p.name: p for p in old_params}
        new_by_name = {p.name: p for p in new_params}

        dropped = [p for p in old_params if p.name not in new_by_name]
        introduced = [p for p in new_params if p.name not in old_by_name]

        changes: list[ApiChange] = []

        # A single swap at the same position reads as a rename not a removal plus an addition
        renamed: set[str] = set()
        if len(dropped) == 1 and len(introduced) == 1:
            before, after = dropped[0], introduced[0]
            if (
                before.kind == after.kind
                and old_params.index(before) == new_params.index(after)
            ):
                renamed = {before.name, after.name}
                changes.append(
                    ApiChange(
                        symbol=new.qualified_name,
                        change_type=ChangeType.PARAMETER_RENAMED,
                        old_signature=old.signature,
                        new_signature=new.signature,
                        details=f"{before.name} -> {after.name}",
                    )
                )

        for param in dropped:
            if param.name in renamed:
                continue
            changes.append(
                ApiChange(
                    symbol=new.qualified_name,
                    change_type=ChangeType.PARAMETER_REMOVED,
                    old_signature=old.signature,
                    new_signature=new.signature,
                    details=f"parameter '{param.name}' removed",
                )
            )

        for param in introduced:
            if param.name in renamed or not param.is_required:
                continue
            changes.append(
                ApiChange(
                    symbol=new.qualified_name,
                    change_type=ChangeType.PARAMETER_ADDED_REQUIRED,
                    old_signature=old.signature,
                    new_signature=new.signature,
                    details=f"required parameter '{param.name}' added",
                )
            )

        for name, before in old_by_name.items():
            after = new_by_name.get(name)
            if after is None or before.default == after.default:
                continue
            changes.append(
                ApiChange(
                    symbol=new.qualified_name,
                    change_type=ChangeType.DEFAULT_CHANGED,
                    old_signature=old.signature,
                    new_signature=new.signature,
                    details=(
                        f"'{name}' default {before.default or 'required'} "
                        f"-> {after.default or 'required'}"
                    ),
                )
            )

        return changes


def _parse_parameters(signature: str | None) -> list[_Param] | None:
    """Recover parameters from a rendered signature such as `get(url, t=None)`"""
    if not signature:
        return None
    try:
        tree = ast.parse(f"def {signature}: pass")
    except SyntaxError:
        return None

    func = tree.body[0]
    if not isinstance(func, ast.FunctionDef):
        return None

    args = func.args
    params: list[_Param] = []

    positional = args.posonlyargs + args.args
    padding: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults))
    for arg, default in zip(positional, padding + list(args.defaults)):
        kind = "posonly" if arg in args.posonlyargs else "positional"
        params.append(_Param(arg.arg, kind, _unparse(default)))

    if args.vararg:
        params.append(_Param(args.vararg.arg, "vararg", None))

    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        params.append(_Param(arg.arg, "kwonly", _unparse(default)))

    if args.kwarg:
        params.append(_Param(args.kwarg.arg, "kwarg", None))

    return params


def _unparse(node: ast.expr | None) -> str | None:
    return ast.unparse(node) if node is not None else None

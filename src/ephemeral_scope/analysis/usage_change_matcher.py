"""Matches project usages against dependency API changes."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ephemeral_scope.domain.enums import ChangeType
from ephemeral_scope.domain.models import AffectedUsage, ApiChange, ApiUsage

#: A newly added symbol cannot break code that already runs, so additions are
#: excluded by default. Every other change type can.
BREAKING_CHANGE_TYPES = frozenset(set(ChangeType) - {ChangeType.ADDED})


class UsageChangeMatcher:
    """Pairs each usage with the API changes that land on it."""

    def match(
        self,
        usages: Sequence[ApiUsage],
        changes: Sequence[ApiChange],
        change_types: Iterable[ChangeType] | None = None,
    ) -> list[AffectedUsage]:
        """Return one record per pair that intersect.

        A single usage can appear more than once when several changes hit the
        same symbol.
        """
        relevant = [
            change
            for change in changes
            if change.change_type
            in (BREAKING_CHANGE_TYPES if change_types is None else set(change_types))
        ]

        affected = [
            AffectedUsage(usage=usage, change=change)
            for usage in usages
            for change in relevant
            if change.affects(usage)
        ]

        affected.sort(
            key=lambda a: (
                str(a.usage.file),
                a.usage.line,
                a.usage.column,
                a.usage.symbol,
                str(a.change.change_type),
            )
        )
        return affected

"""Deciding whether a release-note statement touches the submitted project.

A package's changelog describes everything that changed; a project uses a
small slice of it. This module separates the two, so a report can lead with
"this affects code you wrote" instead of reprinting a changelog.

It lives under `ml` beside the classifier, but the matching is deterministic
symbol comparison, not a learned model. Nothing here is trained. Treating a
statement as relevant because it names `Session.send` and the project calls
`requests.Session.send` is a lookup, and an explainable one: the report can
show the symbol that connected them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ephemeral_scope.domain.enums import ReleaseNoteCategory
from ephemeral_scope.domain.models import (
    ApiChange,
    ApiUsage,
    ClassifiedChange,
    ReleaseNoteItem,
)

#: Score for each kind of connection, strongest first. A statement naming the
#: fully qualified symbol the project imports is near-certain; sharing only a
#: parameter name is a hint worth surfacing but not acting on.
EXACT_QUALIFIED_MATCH = 1.0
FINAL_NAME_MATCH = 0.7
PARAMETER_MATCH = 0.5
PACKAGE_MENTION_ONLY = 0.2
NO_CONNECTION = 0.0

#: Above this a statement is reported as project-relevant.
RELEVANCE_THRESHOLD = 0.5

#: `Session.send`, ``HTTPResponse.read`` - changelog authors mark up symbols.
_BACKTICKED = re.compile(r"`{1,2}([^`\n]{1,120})`{1,2}")
#: requests.Session.send, np.float64 - a dotted path in running prose.
_DOTTED = re.compile(r"\b([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+)\b")
#: get_adapter(), DataFrame.append(...)
_CALL = re.compile(r"\b([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*\(")
#: verify=False, timeout=30 - keyword arguments name parameters.
_PARAMETER = re.compile(r"\b([A-Za-z_][\w]*)\s*=\s*[^=]")
#: CapWords or snake_case identifiers, used only inside backticks.
_IDENTIFIER = re.compile(r"^[A-Za-z_][\w]*$")

#: Words that look like identifiers but carry no API meaning. Without this
#: every statement matches a project that happens to define `test` or `data`.
_STOP_SYMBOLS = frozenset(
    {
        "true",
        "false",
        "none",
        "null",
        "self",
        "cls",
        "python",
        "pypi",
        "github",
        "note",
        "warning",
        "see",
        "the",
        "and",
        "or",
        "not",
        "in",
        "is",
        "if",
        "to",
        "a",
        "an",
        "it",
        "this",
        "that",
    }
)


@dataclass(frozen=True, slots=True)
class RelevanceResult:
    """Why a statement was or was not considered project-relevant."""

    score: float
    mentioned_symbols: tuple[str, ...]
    matched_project_symbols: tuple[str, ...]

    @property
    def is_relevant(self) -> bool:
        return self.score >= RELEVANCE_THRESHOLD


def extract_symbols(text: str) -> tuple[str, ...]:
    """Pull the API names a statement appears to mention.

    Order is not meaningful; duplicates are dropped. Backticked spans are
    trusted most, because an author marking up `Session.send` is naming an
    API on purpose, but bare dotted paths and call expressions are picked up
    too since plenty of changelogs use no markup at all.
    """
    found: list[str] = []

    for match in _BACKTICKED.finditer(text):
        inner = match.group(1).strip()
        # Backticks also wrap prose, flags and whole expressions. Keep the
        # parts that look like identifiers or dotted paths.
        for candidate in re.split(r"[\s,;:()\[\]{}]+", inner):
            candidate = candidate.strip(".'\"")
            if _IDENTIFIER.match(candidate) or _DOTTED.fullmatch(candidate):
                found.append(candidate)

    found += [match.group(1) for match in _DOTTED.finditer(text)]
    found += [match.group(1) for match in _CALL.finditer(text)]

    return _dedupe(name for name in found if _is_meaningful(name))


def extract_parameters(text: str) -> tuple[str, ...]:
    """Pull parameter names from keyword-argument syntax such as ``verify=False``."""
    names = (match.group(1) for match in _PARAMETER.finditer(text))
    return _dedupe(name for name in names if _is_meaningful(name))


def _is_meaningful(name: str) -> bool:
    if not name or name.lower() in _STOP_SYMBOLS:
        return False
    # Single characters are almost always prose or maths, not API names.
    return len(name) > 1 or "." in name


def _dedupe(names: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for name in names:
        seen.setdefault(name, None)
    return tuple(seen)


def _final_name(symbol: str) -> str:
    return symbol.rsplit(".", 1)[-1]


class RelevanceMatcher:
    """Scores release-note statements against what a project actually uses.

    Built once per analysis from the project's usages and the API changes
    found between the two versions, then asked about each statement.
    """

    def __init__(
        self,
        usages: Sequence[ApiUsage] = (),
        changes: Sequence[ApiChange] = (),
        package_name: str | None = None,
    ) -> None:
        self.package_name = package_name
        #: Fully qualified names the project refers to, e.g. requests.Session.
        self._qualified: dict[str, str] = {}
        #: Final components mapped back to the qualified name that produced
        #: them, so a statement saying only `Session` still resolves.
        self._final_names: dict[str, str] = {}
        #: Parameter names appearing in signatures that changed.
        self._parameters: dict[str, str] = {}

        for usage in usages:
            self._add_symbol(usage.symbol)
        for change in changes:
            self._add_symbol(change.symbol)
            self._add_parameters(change)

    def _add_symbol(self, symbol: str) -> None:
        if not symbol:
            return
        self._qualified.setdefault(symbol, symbol)
        self._final_names.setdefault(_final_name(symbol), symbol)

    def _add_parameters(self, change: ApiChange) -> None:
        """Record parameter names from a change's signatures.

        A note saying "the `verify` argument now defaults to True" names no
        class or function, so the only way to connect it to the project is
        through the parameters of the signatures that moved.
        """
        for signature in (change.old_signature, change.new_signature):
            if not signature:
                continue
            for name in re.findall(r"\b([a-z_][\w]*)\s*(?:[:=,)])", signature):
                if _is_meaningful(name):
                    self._parameters.setdefault(name, change.symbol)

    def score(self, text: str) -> RelevanceResult:
        """Rate how strongly a statement connects to the project.

        The strongest single connection wins rather than accumulating, so a
        statement naming five unrelated symbols plus one real match does not
        outrank a statement naming only the real match.
        """
        mentioned = extract_symbols(text)
        parameters = extract_parameters(text)

        best = NO_CONNECTION
        matched: list[str] = []

        for name in mentioned:
            if name in self._qualified:
                best = max(best, EXACT_QUALIFIED_MATCH)
                matched.append(self._qualified[name])
                continue
            final = _final_name(name)
            if final in self._final_names:
                best = max(best, FINAL_NAME_MATCH)
                matched.append(self._final_names[final])

        for name in parameters:
            if name in self._parameters:
                best = max(best, PARAMETER_MATCH)
                matched.append(self._parameters[name])

        if best == NO_CONNECTION and self._mentions_package(text):
            best = PACKAGE_MENTION_ONLY

        return RelevanceResult(
            score=best,
            mentioned_symbols=tuple(mentioned) + tuple(parameters),
            matched_project_symbols=_dedupe(matched),
        )

    def _mentions_package(self, text: str) -> bool:
        if not self.package_name:
            return False
        return (
            re.search(rf"\b{re.escape(self.package_name)}\b", text, re.I) is not None
        )

    def match(
        self,
        note: ReleaseNoteItem,
        category: ReleaseNoteCategory | None = None,
        confidence: float = 0.0,
    ) -> ClassifiedChange:
        """Attach relevance evidence to one statement."""
        result = self.score(note.text)
        return ClassifiedChange(
            note=note,
            category=category,
            confidence=confidence,
            mentioned_symbols=result.mentioned_symbols,
            matched_project_symbols=result.matched_project_symbols,
            relevance_score=result.score,
        )

    def partition(
        self, changes: Sequence[ClassifiedChange]
    ) -> tuple[list[ClassifiedChange], list[ClassifiedChange]]:
        """Split classified changes into project-relevant and general.

        Returns ``(relevant, general)``. Relevance is scored from the note's
        own text, so this works whether the categories came from the rules,
        the model, or neither.
        """
        relevant: list[ClassifiedChange] = []
        general: list[ClassifiedChange] = []

        for change in changes:
            result = self.score(change.note.text)
            scored = ClassifiedChange(
                note=change.note,
                category=change.category,
                confidence=change.confidence,
                mentioned_symbols=result.mentioned_symbols,
                matched_project_symbols=result.matched_project_symbols,
                relevance_score=result.score,
                decision=change.decision,
            )
            (relevant if result.is_relevant else general).append(scored)

        return relevant, general

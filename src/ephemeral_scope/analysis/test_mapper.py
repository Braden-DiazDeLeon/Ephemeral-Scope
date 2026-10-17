"""Test file mapping."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ephemeral_scope.domain.models import ApiUsage, ProjectManifest, TestReference


class TestMapper:
    """Links affected source files or symbols to the tests likely to cover them."""

    def map(
        self, manifest: ProjectManifest, usages: list[ApiUsage]
    ) -> list[TestReference]:
        """Build references from each test file to the affected sources it covers."""
        affected = {usage.file for usage in usages}
        if not affected:
            return []

        # Source stem is affected files sharing that stem
        by_stem: dict[str, list[Path]] = {}
        for source in affected:
            by_stem.setdefault(source.stem, []).append(source)

        symbols_by_file: dict[Path, set[str]] = {}
        for usage in usages:
            symbols_by_file.setdefault(usage.file, set()).add(usage.symbol)

        references: list[TestReference] = []
        seen: set[tuple[Path, Path, str | None]] = set()

        def add(test_file: Path, source_file: Path, symbol: str | None) -> None:
            key = (test_file, source_file, symbol)
            if key not in seen:
                seen.add(key)
                references.append(
                    TestReference(
                        test_file=test_file,
                        source_file=source_file,
                        related_symbol=symbol,
                    )
                )

        for test_file in manifest.test_files:
            text = _read(test_file)
            if text is None:
                continue

            matched: set[Path] = set()

            subject = _subject_stem(test_file)
            for source in by_stem.get(subject, []):
                matched.add(source)

            for module in _imported_modules(text):
                for segment in module.split("."):
                    for source in by_stem.get(segment, []):
                        matched.add(source)

            for source in matched:
                add(test_file, source, None)

            identifiers = _identifiers(text)
            for source, symbols in symbols_by_file.items():
                for symbol in symbols:
                    leaf = symbol.rsplit(".", 1)[-1]
                    if leaf in identifiers:
                        add(test_file, source, symbol)

        return references


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _subject_stem(test_file: Path) -> str:
    """Strip the test naming convention to recover the module under test."""
    stem = test_file.stem
    if stem.startswith("test_"):
        return stem[len("test_") :]
    if stem.endswith("_test"):
        return stem[: -len("_test")]
    return stem


def _identifiers(text: str) -> set[str]:
    """Whole word tokens in the file, so `get` does not match inside `target`"""
    return set(re.findall(r"\b\w+\b", text))


def _imported_modules(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
            modules.extend(alias.name for alias in node.names)
    return modules

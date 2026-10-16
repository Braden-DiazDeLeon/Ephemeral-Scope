"""Dependency file parsing  pyproject.toml and requirements.txt."""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement

from ephemeral_scope.domain.models import Dependency, ProjectManifest


class DependencyParser:
    """Reads requirements.txt and pyproject.toml to produce a dependency list."""

    def parse(self, manifest: ProjectManifest) -> list[Dependency]:
        """Return a merged duplicated dependency list from all discovered files."""
        seen: dict[str, Dependency] = {}

        for dep_file in manifest.dependency_files:
            if dep_file.name == "pyproject.toml":
                deps = self._parse_pyproject(dep_file)
            elif dep_file.name == "requirements.txt":
                deps = self._parse_requirements_txt(dep_file)
            else:
                continue

            for dep in deps:
                key = dep.name.lower()
                if key not in seen:
                    seen[key] = dep

        return list(seen.values())

    @staticmethod
    def _parse_pyproject(path: Path) -> list[Dependency]:
        with path.open("rb") as f:
            data = tomllib.load(f)

        raw_deps: list[str] = data.get("project", {}).get("dependencies", [])
        results: list[Dependency] = []
        for raw in raw_deps:
            req = Requirement(raw)
            specifier = str(req.specifier) if req.specifier else None
            results.append(Dependency(name=req.name, specifier=specifier, source_file=path))
        return results

    @staticmethod
    def _parse_requirements_txt(path: Path) -> list[Dependency]:
        results: list[Dependency] = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            req = Requirement(line)
            specifier = str(req.specifier) if req.specifier else None
            results.append(Dependency(name=req.name, specifier=specifier, source_file=path))
        return results

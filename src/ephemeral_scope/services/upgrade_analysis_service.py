"""Top-level use-case orchestrator."""

from __future__ import annotations

from pathlib import Path

from ephemeral_scope.analysis.ast_usage_analyzer import AstUsageAnalyzer
from ephemeral_scope.analysis.usage_change_matcher import UsageChangeMatcher
from ephemeral_scope.domain.models import (
    AffectedUsage,
    AnalysisRequest,
    ApiChange,
    ApiUsage,
    ProjectManifest,
)
from ephemeral_scope.ingestion.project_loader import ProjectLoader
from ephemeral_scope.packages.api_comparator import ApiComparator
from ephemeral_scope.packages.api_snapshot_builder import ApiSnapshotBuilder


class UpgradeAnalysisService:
    """Owns the use case: analyze(request) -> UpgradeReport.

    Collaborators are injected so the pipeline can be exercised without
    reaching out to PyPI.
    """

    def __init__(
        self,
        project_loader: ProjectLoader | None = None,
        usage_analyzer: AstUsageAnalyzer | None = None,
        snapshot_builder: ApiSnapshotBuilder | None = None,
        comparator: ApiComparator | None = None,
        matcher: UsageChangeMatcher | None = None,
    ) -> None:
        self.project_loader = project_loader or ProjectLoader()
        self.usage_analyzer = usage_analyzer or AstUsageAnalyzer()
        self.snapshot_builder = snapshot_builder or ApiSnapshotBuilder()
        self.comparator = comparator or ApiComparator()
        self.matcher = matcher or UsageChangeMatcher()

    def find_affected_usages(self, request: AnalysisRequest) -> list[AffectedUsage]:
        """Report the places in the project that the upgrade lands on."""
        manifest = self.load_project(request.project_path)
        usages = self.usage_analyzer.analyze(manifest, request.package_name)
        changes = self.compare_versions(request)
        return self.matcher.match(usages, changes)

    def load_project(self, project_path: Path) -> ProjectManifest:
        """Accept either a directory or a ZIP archive."""
        path = Path(project_path)
        if path.is_file() and path.suffix == ".zip":
            return self.project_loader.load_zip(path)
        return self.project_loader.load_directory(path)

    def compare_versions(self, request: AnalysisRequest) -> list[ApiChange]:
        old = self.snapshot_builder.build(
            request.package_name, request.current_version
        )
        new = self.snapshot_builder.build(request.package_name, request.target_version)
        return self.comparator.compare(old, new)

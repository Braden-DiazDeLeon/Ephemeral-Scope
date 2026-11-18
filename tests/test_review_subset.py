"""Tests for the manual-review sampler in scripts/make_review_subset.py."""

from __future__ import annotations

import importlib.util
from collections import Counter
from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ReleaseNoteCategory as Category
from ephemeral_scope.ml.dataset import LabeledNote

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "make_review_subset.py"


def _load_script():
    """Import the script by path; `scripts/` is deliberately not a package."""
    spec = importlib.util.spec_from_file_location("make_review_subset", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


make_review_subset = _load_script()
balanced_sample = make_review_subset.balanced_sample


def note(text: str, label: Category | None) -> LabeledNote:
    return LabeledNote(
        text=text,
        package_name="numpy",
        release_version="1.0.0",
        source_url=None,
        section=None,
        suggested_label=label,
    )


def corpus(**counts: int) -> list[LabeledNote]:
    notes = []
    for name, total in counts.items():
        category = Category(name)
        notes += [note(f"{name} statement {i}", category) for i in range(total)]
    return notes


class TestBalancedSample:
    def test_caps_each_category_at_the_budget(self):
        sample = balanced_sample(corpus(bug_fix=500, feature=500), per_label=10, unlabelled=0, seed=1)

        counts = Counter(n.suggested_label.value for n in sample)
        assert counts == {"bug_fix": 10, "feature": 10}

    def test_scarce_categories_contribute_everything_they_have(self):
        sample = balanced_sample(
            corpus(bug_fix=500, security_fix=3), per_label=10, unlabelled=0, seed=1
        )

        counts = Counter(n.suggested_label.value for n in sample)
        assert counts["security_fix"] == 3
        assert counts["bug_fix"] == 10

    def test_rare_category_does_not_truncate_the_others(self):
        """The point of the sampler: one scarce class must not shrink the rest."""
        sample = balanced_sample(
            corpus(bug_fix=500, security_fix=1), per_label=25, unlabelled=0, seed=1
        )

        assert len(sample) == 26

    def test_unlabelled_notes_are_skipped_without_a_budget(self):
        sample = balanced_sample(
            [note("no suggestion", None)], per_label=10, unlabelled=0, seed=1
        )

        assert sample == []


class TestUnlabelledBudget:
    """Rule misses are where TF-IDF can beat the keywords, so they must be
    reviewable rather than invisible."""

    def test_budget_pulls_in_rule_misses(self):
        source = corpus(bug_fix=100) + [note(f"miss {i}", None) for i in range(50)]

        sample = balanced_sample(source, per_label=10, unlabelled=20, seed=1)

        assert sum(1 for n in sample if n.suggested_label is None) == 20

    def test_budget_is_capped_by_availability(self):
        source = corpus(bug_fix=100) + [note(f"miss {i}", None) for i in range(3)]

        sample = balanced_sample(source, per_label=10, unlabelled=20, seed=1)

        assert sum(1 for n in sample if n.suggested_label is None) == 3

    def test_budget_does_not_displace_labelled_categories(self):
        source = corpus(bug_fix=100) + [note(f"miss {i}", None) for i in range(50)]

        sample = balanced_sample(source, per_label=10, unlabelled=20, seed=1)

        assert sum(1 for n in sample if n.suggested_label is not None) == 10
        assert len(sample) == 30

    def test_misses_are_sampled_not_truncated(self):
        source = [note(f"miss {i}", None) for i in range(50)]

        first = balanced_sample(source, per_label=0, unlabelled=10, seed=1)
        second = balanced_sample(source, per_label=0, unlabelled=10, seed=2)

        assert [n.text for n in first] != [n.text for n in second]
        assert {n.text for n in first} < {n.text for n in source}

    def test_same_seed_gives_the_same_sample(self):
        source = corpus(bug_fix=200)

        first = balanced_sample(source, per_label=20, unlabelled=0, seed=7)
        second = balanced_sample(source, per_label=20, unlabelled=0, seed=7)

        assert [n.text for n in first] == [n.text for n in second]

    def test_different_seeds_give_different_samples(self):
        source = corpus(bug_fix=200)

        first = balanced_sample(source, per_label=20, unlabelled=0, seed=7)
        second = balanced_sample(source, per_label=20, unlabelled=0, seed=8)

        assert [n.text for n in first] != [n.text for n in second]

    def test_categories_are_interleaved(self):
        """Unshuffled output would let a reviewer coast on runs of one label."""
        sample = balanced_sample(corpus(bug_fix=100, feature=100), per_label=50, unlabelled=0, seed=3)

        labels = [n.suggested_label.value for n in sample]
        assert labels != sorted(labels)

    def test_sample_is_drawn_from_the_source(self):
        source = corpus(bug_fix=30)

        sample = balanced_sample(source, per_label=10, unlabelled=0, seed=1)

        texts = {n.text for n in source}
        assert all(n.text in texts for n in sample)
        assert len({n.text for n in sample}) == 10


@pytest.mark.parametrize("per_label", [1, 5, 60])
def test_never_returns_more_than_the_budget_per_category(per_label: int):
    sample = balanced_sample(corpus(bug_fix=100, feature=100), per_label, unlabelled=0, seed=2)

    counts = Counter(n.suggested_label.value for n in sample)
    assert max(counts.values()) <= per_label

"""Tests for the hybrid rule/model selection policy.

The policy exists so a disagreement between the deterministic rules and the
TF-IDF model is recorded rather than silently resolved. These tests pin the
four outcomes of the hierarchy plus the two rule-only sources.
"""

from __future__ import annotations

import pytest

from ephemeral_scope.domain.enums import ReleaseNoteCategory as Category
from ephemeral_scope.domain.enums import SelectionReason
from ephemeral_scope.ml.release_note_classifier import RuleOutcome, decide


def rule(category: Category | None, confidence: float = 0.5) -> RuleOutcome:
    source = SelectionReason.KEYWORD_RULE if category else SelectionReason.NO_EVIDENCE
    return RuleOutcome(category, confidence, source)


def no_rule() -> RuleOutcome:
    return RuleOutcome(None, 0.0, SelectionReason.NO_EVIDENCE)


class TestRuleAndModelAgree:
    def test_agreement_selects_the_shared_category(self):
        decision = decide(rule(Category.SECURITY_FIX), Category.SECURITY_FIX, 0.6)

        assert decision.selected_category is Category.SECURITY_FIX
        assert decision.agreement is True
        assert decision.selection_reason is SelectionReason.RULE_MODEL_AGREEMENT

    def test_agreement_raises_confidence_above_the_rule_alone(self):
        alone = decide(rule(Category.BUG_FIX, 0.5), None, 0.0)
        agreed = decide(rule(Category.BUG_FIX, 0.5), Category.BUG_FIX, 0.6)

        assert agreed.confidence > alone.confidence

    def test_confidence_stays_below_certainty(self):
        decision = decide(rule(Category.BUG_FIX, 0.8), Category.BUG_FIX, 0.99)

        assert decision.confidence <= 0.95


class TestRuleAndModelDisagree:
    def test_the_rule_wins(self):
        decision = decide(rule(Category.SECURITY_FIX), Category.BUG_FIX, 0.9)

        assert decision.selected_category is Category.SECURITY_FIX
        assert decision.selection_reason is SelectionReason.RULE_PREFERRED_OVER_MODEL
        assert decision.agreement is False

    def test_a_confident_model_still_does_not_override(self):
        """The model's confidence is not a vote; it cannot outrank a rule."""
        decision = decide(rule(Category.DEPRECATION, 0.5), Category.FEATURE, 1.0)

        assert decision.selected_category is Category.DEPRECATION
        assert decision.confidence == pytest.approx(0.5)

    def test_both_answers_survive_for_inspection(self):
        decision = decide(rule(Category.SECURITY_FIX), Category.BUG_FIX, 0.9)

        assert decision.rule_category is Category.SECURITY_FIX
        assert decision.model_category is Category.BUG_FIX


class TestOnlyTheRuleProducesAResult:
    def test_section_rule_is_named_as_the_reason(self):
        outcome = RuleOutcome(Category.SECURITY_FIX, 0.8, SelectionReason.SECTION_RULE)

        decision = decide(outcome, None, 0.0)

        assert decision.selected_category is Category.SECURITY_FIX
        assert decision.selection_reason is SelectionReason.SECTION_RULE

    def test_keyword_rule_is_named_as_the_reason(self):
        decision = decide(rule(Category.BUG_FIX), None, 0.0)

        assert decision.selection_reason is SelectionReason.KEYWORD_RULE

    def test_confidence_comes_from_the_rule(self):
        decision = decide(rule(Category.BUG_FIX, 0.8), None, 0.0)

        assert decision.confidence == pytest.approx(0.8)
        assert decision.agreement is False


class TestOnlyTheModelProducesAResult:
    def test_model_supplies_the_category(self):
        decision = decide(no_rule(), Category.BEHAVIORAL_CHANGE, 0.7)

        assert decision.selected_category is Category.BEHAVIORAL_CHANGE
        assert decision.selection_reason is SelectionReason.MODEL_SUGGESTION_ONLY
        assert decision.confidence == pytest.approx(0.7)

    def test_it_is_flagged_so_risk_rules_can_discount_it(self):
        decision = decide(no_rule(), Category.BREAKING_CHANGE, 0.9)

        assert decision.is_model_only is True

    def test_a_corroborated_category_is_not_model_only(self):
        decision = decide(rule(Category.BREAKING_CHANGE), Category.BREAKING_CHANGE, 0.9)

        assert decision.is_model_only is False


class TestNeitherProducesAResult:
    def test_no_category_is_invented(self):
        decision = decide(no_rule(), None, 0.0)

        assert decision.selected_category is None
        assert decision.selection_reason is SelectionReason.NO_EVIDENCE
        assert decision.confidence == 0.0

    def test_unmatched_is_not_the_same_as_irrelevant(self):
        """The distinction the whole decision object exists to preserve."""
        unmatched = decide(no_rule(), None, 0.0)
        irrelevant = decide(rule(Category.IRRELEVANT), None, 0.0)

        assert unmatched.selected_category is None
        assert irrelevant.selected_category is Category.IRRELEVANT
        assert unmatched.selected_category != irrelevant.selected_category


class TestSerialization:
    def test_decision_round_trips_to_json_safe_values(self):
        decision = decide(rule(Category.SECURITY_FIX), Category.BUG_FIX, 0.9)

        document = decision.to_dict()

        assert document["selected_category"] == "security_fix"
        assert document["model_category"] == "bug_fix"
        assert document["selection_reason"] == "rule_preferred_over_model"
        assert document["agreement"] is False

    def test_absent_categories_serialize_as_null(self):
        document = decide(no_rule(), None, 0.0).to_dict()

        assert document["selected_category"] is None
        assert document["rule_category"] is None
        assert document["model_category"] is None

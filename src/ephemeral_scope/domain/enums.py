"""Domain enumerations."""

from enum import StrEnum


class ChangeType(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    SIGNATURE_CHANGED = "signature_changed"
    PARAMETER_ADDED_REQUIRED = "parameter_added_required"
    PARAMETER_REMOVED = "parameter_removed"
    PARAMETER_RENAMED = "parameter_renamed"
    DEFAULT_CHANGED = "default_changed"
    MOVED = "moved"
    RETURN_TYPE_CHANGED = "return_type_changed"


class ReleaseNoteCategory(StrEnum):
    BREAKING_CHANGE = "breaking_change"
    DEPRECATION = "deprecation"
    SECURITY_FIX = "security_fix"
    BEHAVIORAL_CHANGE = "behavioral_change"
    BUG_FIX = "bug_fix"
    FEATURE = "feature"
    IRRELEVANT = "irrelevant"


class SelectionReason(StrEnum):
    """Where a :class:`ClassificationDecision` got its selected category.

    Recorded so a disagreement between the rules and the model stays visible
    in the report instead of being silently resolved.
    """

    #: A changelog heading mapped straight to a category.
    SECTION_RULE = "section_rule"
    #: No usable heading, but a keyword pattern matched the prose.
    KEYWORD_RULE = "keyword_rule"
    #: Rule and model independently chose the same category.
    RULE_MODEL_AGREEMENT = "rule_model_agreement"
    #: They disagreed; the deterministic rule wins.
    RULE_PREFERRED_OVER_MODEL = "rule_preferred_over_model"
    #: No rule matched, so the category rests on the model alone.
    MODEL_SUGGESTION_ONLY = "model_suggestion_only"
    #: Neither produced a category. Distinct from IRRELEVANT.
    NO_EVIDENCE = "no_evidence"


class RiskLevel(StrEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class UsageKind(StrEnum):
    IMPORT = "import"
    FUNCTION_CALL = "function_call"
    METHOD_CALL = "method_call"
    CLASS_REFERENCE = "class_reference"
    INHERITANCE = "inheritance"


class ApiSymbolKind(StrEnum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    ATTRIBUTE = "attribute"

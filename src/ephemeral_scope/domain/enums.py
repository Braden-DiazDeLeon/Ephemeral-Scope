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

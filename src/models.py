"""Core data models for the Architecture Review Agent.

Defines dataclasses for the resource graph, rules, findings, review response,
and custom error classes used throughout the processing pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Resource Graph Models
# ---------------------------------------------------------------------------


@dataclass
class ResourceNode:
    """A single CloudFormation resource extracted from a template."""

    logical_id: str
    resource_type: str
    properties: dict[str, Any]


@dataclass
class ResourceEdge:
    """A directed reference between two resources in the template."""

    source: str
    target: str
    reference_type: str  # "Ref" | "Fn::GetAtt" | "Fn::Sub" | "DependsOn"
    attribute: str | None = None  # For Fn::GetAtt, the attribute name


@dataclass
class ArchPattern:
    """An architectural pattern detected from resource relationships."""

    pattern_type: str  # "async_pipeline" | "event_driven" | "request_response"
    resources: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class ResourceGraph:
    """Directed acyclic graph of CloudFormation resources and their relationships."""

    nodes: list[ResourceNode] = field(default_factory=list)
    edges: list[ResourceEdge] = field(default_factory=list)
    patterns: list[ArchPattern] = field(default_factory=list)
    template_format: str = "yaml"  # "yaml" | "json"


# ---------------------------------------------------------------------------
# Rules Models
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    """A built-in rule from wa_rules.json for static analysis."""

    id: str
    pillar: str
    category: str
    principle: str
    title: str
    description: str
    severity: str  # "critical" | "warning" | "info"
    resource_types: list[str] = field(default_factory=list)
    check: str = ""
    fix_hint: str = ""


@dataclass
class OrgRule:
    """An organization-specific rule persisted in AgentCore Memory."""

    rule_id: str
    rule_text: str  # 1-500 characters
    severity: str  # "critical" | "warning" | "info"
    pillar: str | None = None
    created_at: str = ""  # ISO 8601 timestamp
    org_id: str = ""


# ---------------------------------------------------------------------------
# Findings Models
# ---------------------------------------------------------------------------


@dataclass
class StaticFinding:
    """A finding produced by the static analysis engine."""

    rule_id: str
    severity: str  # "critical" | "warning" | "info"
    pillar: str
    resource_logical_id: str
    title: str
    description: str
    source: str = "static"


@dataclass
class SemanticFinding:
    """A finding produced by the semantic analysis engine."""

    severity: str  # "critical" | "warning" | "info"
    pillar: str
    resource_logical_id: str
    title: str
    description: str
    suggested_fix: str = ""
    source: str = "semantic"


@dataclass
class Fix:
    """A code fix for a finding."""

    description: str
    code: str | None = None


@dataclass
class Finding:
    """A composed finding in the final review response."""

    id: str  # F001..F999
    severity: str  # "critical" | "warning" | "info"
    pillar: str
    resource: str  # "LogicalId (AWS::Type)"
    title: str
    description: str
    source: str  # "static" | "semantic" | "org_rule"
    fix: Fix = field(default_factory=lambda: Fix(description=""))
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Review Response Models
# ---------------------------------------------------------------------------


@dataclass
class ReviewSummary:
    """Summary statistics for a review response."""

    total_resources: int = 0
    total_findings: int = 0
    critical: int = 0
    warning: int = 0
    info: int = 0
    passed_checks: int = 0


@dataclass
class ReviewResponse:
    """The complete review response returned to the MCP client."""

    summary: ReviewSummary = field(default_factory=ReviewSummary)
    findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Error Classes
# ---------------------------------------------------------------------------


class ParseError(Exception):
    """Raised when a template cannot be parsed as valid YAML or JSON."""

    def __init__(self, line_number: int, description: str) -> None:
        self.line_number = line_number
        self.description = description
        super().__init__(
            f"Template parse error at line {line_number}: {description}"
        )


class EmptyTemplateError(Exception):
    """Raised when a template contains no reviewable resources."""

    def __init__(self) -> None:
        super().__init__("Template contains no reviewable resources")


class FormatMismatchError(Exception):
    """Raised when declared format doesn't match actual template content."""

    def __init__(self, declared_format: str) -> None:
        self.declared_format = declared_format
        super().__init__(
            f"Format mismatch: declared '{declared_format}' but content is not valid CloudFormation"
        )


class InvalidFormatError(Exception):
    """Raised when format parameter is not 'cloudformation'."""

    def __init__(self, format_value: str) -> None:
        self.format_value = format_value
        super().__init__(
            "Only 'cloudformation' format is supported in this version"
        )


class InvalidPillarError(Exception):
    """Raised when an invalid focus_pillars value is provided."""

    VALID_PILLARS = frozenset({
        "security",
        "reliability",
        "performance_efficiency",
        "cost_optimization",
        "operational_excellence",
        "sustainability",
    })

    def __init__(self, value: str) -> None:
        self.value = value
        valid = ", ".join(sorted(self.VALID_PILLARS))
        super().__init__(
            f"Invalid pillar '{value}'. Valid values: {valid}"
        )


class OrgRuleValidationError(Exception):
    """Raised when org rule parameters fail validation."""

    def __init__(self, field_name: str, reason: str) -> None:
        self.field_name = field_name
        self.reason = reason
        super().__init__(f"Rule validation failed: {field_name} {reason}")


class OrgRuleNotFoundError(Exception):
    """Raised when attempting to remove a non-existent org rule."""

    def __init__(self, rule_id: str) -> None:
        self.rule_id = rule_id
        super().__init__(f"Org rule '{rule_id}' not found")


class OrgRuleLimitError(Exception):
    """Raised when the maximum org rule limit (200) is reached."""

    def __init__(self) -> None:
        super().__init__(
            "Maximum org rule limit (200) reached. "
            "Remove existing rules before adding new ones."
        )


class ResourceLimitError(Exception):
    """Raised when a template exceeds the maximum supported resource count."""

    def __init__(self) -> None:
        super().__init__(
            "Template exceeds maximum supported resource count of 200"
        )

"""Static analysis engine for CloudFormation templates.

Evaluates resources against the built-in wa_rules.json rule set using
dot-notation path checks into resource properties.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.models import (
    InvalidPillarError,
    ResourceGraph,
    Rule,
    StaticFinding,
)

_VALID_PILLARS = frozenset({
    "security",
    "reliability",
    "performance_efficiency",
    "cost_optimization",
    "operational_excellence",
    "sustainability",
})

_DEFAULT_RULES_PATH = str(Path(__file__).parent / "rules" / "wa_rules.json")


def load_rules(rules_path: str | None = None) -> list[Rule]:
    """Load rules from wa_rules.json file.

    Args:
        rules_path: Optional path to the rules JSON file.
                    Defaults to src/rules/wa_rules.json.

    Returns:
        List of Rule objects loaded from the file.
    """
    path = rules_path or _DEFAULT_RULES_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rules: list[Rule] = []
    for entry in data.get("rules", []):
        rules.append(
            Rule(
                id=entry["id"],
                pillar=entry["pillar"],
                category=entry["category"],
                principle=entry["principle"],
                title=entry["title"],
                description=entry["description"],
                severity=entry["severity"],
                resource_types=entry.get("resource_types", []),
                check=entry.get("check", ""),
                fix_hint=entry.get("fix_hint", ""),
            )
        )
    return rules


def run_static_analysis(
    graph: ResourceGraph,
    rules: list[Rule],
    focus_pillars: list[str] | None = None,
) -> tuple[list[StaticFinding], int]:
    """Run static analysis on all resources against applicable rules.

    Args:
        graph: Parsed ResourceGraph.
        rules: Loaded rules from wa_rules.json.
        focus_pillars: Optional filter to limit analysis to specific pillars.

    Returns:
        Tuple of (findings list, passed_checks count).

    Raises:
        InvalidPillarError: If focus_pillars contains invalid values.
    """
    # Validate focus_pillars
    if focus_pillars is not None:
        for pillar in focus_pillars:
            if pillar not in _VALID_PILLARS:
                raise InvalidPillarError(pillar)

    # Filter rules by focus_pillars if specified
    if focus_pillars is not None:
        pillar_set = set(focus_pillars)
        active_rules = [r for r in rules if r.pillar in pillar_set]
    else:
        active_rules = rules

    findings: list[StaticFinding] = []
    passed_checks = 0

    for node in graph.nodes:
        # Find rules applicable to this resource type
        applicable_rules = [
            r for r in active_rules if node.resource_type in r.resource_types
        ]

        # Skip resources with no applicable rules
        if not applicable_rules:
            continue

        for rule in applicable_rules:
            if _evaluate_check(rule.check, node.properties):
                # Check passed — resource satisfies the rule
                passed_checks += 1
            else:
                # Check failed — produce a finding
                findings.append(
                    StaticFinding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        pillar=rule.pillar,
                        resource_logical_id=node.logical_id,
                        title=rule.title,
                        description=rule.description,
                        source="static",
                    )
                )

    return findings, passed_checks


def _evaluate_check(check: str, properties: dict[str, Any]) -> bool:
    """Evaluate a rule's check expression against resource properties.

    The check is treated as a dot-notation path into the properties dict.
    If the path resolves to a truthy value, the check passes.
    If the path leads to None, a missing key, or a falsy value, the check fails.

    Args:
        check: Dot-notation path string (e.g., "BucketEncryption" or
               "PublicAccessBlockConfiguration.BlockPublicAcls").
        properties: The resource's properties dictionary.

    Returns:
        True if the path resolves to a truthy value (resource passes the check),
        False otherwise (resource fails, producing a finding).
    """
    if not check:
        return True

    # Use the first segment path as the dot-notation property path
    # The check field may contain complex expressions; extract the
    # dot-notation property path (first contiguous sequence of word.word segments)
    path = _extract_property_path(check)
    if not path:
        # If we can't extract a path, treat as a pass (can't evaluate)
        return True

    return _resolve_path(path, properties)


def _extract_property_path(check: str) -> str:
    """Extract a dot-notation property path from a check expression.

    Many check expressions are complex human-readable descriptions.
    We extract the first meaningful dot-separated path of property names.
    If the check starts with 'properties.', we strip that prefix since
    we're already navigating within properties.

    Returns:
        A dot-notation path string, or empty string if none found.
    """
    # Strip leading 'properties.' prefix if present
    text = check
    if text.startswith("properties."):
        text = text[len("properties."):]

    # Try to extract a simple property path from the beginning of the check
    # A property path is a sequence of identifiers separated by dots
    # Stop at spaces, operators, brackets with complex content, etc.
    parts: list[str] = []
    i = 0
    while i < len(text):
        # Collect an identifier (alphanumeric + underscore)
        start = i
        while i < len(text) and (text[i].isalnum() or text[i] == '_'):
            i += 1

        if i == start:
            # No identifier found at this position
            break

        segment = text[start:i]
        parts.append(segment)

        # Skip array notation like [] if present
        if i < len(text) and text[i] == '[':
            bracket_end = text.find(']', i)
            if bracket_end != -1:
                i = bracket_end + 1

        # Check for dot separator
        if i < len(text) and text[i] == '.':
            i += 1  # skip the dot and continue to next segment
        else:
            break

    if not parts:
        return ""

    return ".".join(parts)


def _resolve_path(path: str, properties: dict[str, Any]) -> bool:
    """Resolve a dot-notation path into a properties dictionary.

    Returns True if the path resolves to a truthy value.
    """
    segments = path.split(".")
    current: Any = properties

    for segment in segments:
        if isinstance(current, dict):
            if segment not in current:
                return False
            current = current[segment]
        elif isinstance(current, list):
            # For lists, check if any element has the segment
            found = False
            for item in current:
                if isinstance(item, dict) and segment in item:
                    current = item[segment]
                    found = True
                    break
            if not found:
                return False
        else:
            return False

    # The path resolved; check if the value is truthy
    return bool(current)

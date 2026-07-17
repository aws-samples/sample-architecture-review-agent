"""Response Composer for the Architecture Review Agent.

Merges static and semantic findings, deduplicates, sorts by severity,
assigns sequential IDs (F001, F002, ...), and computes summary statistics.
"""

from __future__ import annotations

from difflib import SequenceMatcher

from src.models import (
    Finding,
    Fix,
    ResourceGraph,
    ReviewResponse,
    ReviewSummary,
    SemanticFinding,
    StaticFinding,
)

# Severity sort order: critical (highest) > warning > info (lowest)
_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _normalize_intent(text: str) -> str:
    """Normalize a rule title/description for intent comparison."""
    return text.strip().lower()


def _intents_match(static_title: str, semantic_title: str) -> bool:
    """Determine if a static finding and semantic finding address the same issue.

    Uses SequenceMatcher to detect similar intent between rule titles.
    A ratio >= 0.6 is considered a match (same general issue).
    """
    a = _normalize_intent(static_title)
    b = _normalize_intent(semantic_title)
    if a == b:
        return True
    return SequenceMatcher(None, a, b).ratio() >= 0.6


def _merge_fixes(static_fix: Fix | None, semantic_fix: Fix | None) -> Fix:
    """Merge fix suggestions from both static and semantic findings.

    Combines descriptions from both fixes, keeping code from whichever
    has it (preferring semantic if both have code).
    """
    if static_fix is None and semantic_fix is None:
        return Fix(description="")
    if static_fix is None:
        return semantic_fix  # type: ignore[return-value]
    if semantic_fix is None:
        return static_fix

    # Merge descriptions
    parts: list[str] = []
    if semantic_fix.description:
        parts.append(semantic_fix.description)
    if static_fix.description and static_fix.description != semantic_fix.description:
        parts.append(static_fix.description)

    merged_description = "\n".join(parts) if parts else ""

    # Prefer semantic code, fall back to static
    code = semantic_fix.code if semantic_fix.code is not None else static_fix.code

    return Fix(description=merged_description, code=code)


def _resource_display(logical_id: str, graph: ResourceGraph) -> str:
    """Build display string 'LogicalId (AWS::Type)' from the resource graph."""
    for node in graph.nodes:
        if node.logical_id == logical_id:
            return f"{logical_id} ({node.resource_type})"
    # Fallback if not found in graph
    return logical_id


def _deduplicate(
    static_findings: list[StaticFinding],
    semantic_findings: list[SemanticFinding],
    fixes: dict[str, Fix],
) -> list[tuple[StaticFinding | SemanticFinding, Fix]]:
    """Deduplicate findings by (resource_logical_id, pillar, rule intent).

    When duplicates are detected, retain the semantic finding (richer context)
    and merge fix suggestions from both.
    """
    # Index semantic findings by (resource_logical_id, pillar) for lookup
    semantic_by_key: dict[tuple[str, str], list[tuple[SemanticFinding, int]]] = {}
    for idx, sf in enumerate(semantic_findings):
        key = (sf.resource_logical_id, sf.pillar)
        semantic_by_key.setdefault(key, []).append((sf, idx))

    # Track which semantic findings have been matched (to avoid double-counting)
    matched_semantic_indices: set[int] = set()

    # Result list of (finding, fix) tuples
    result: list[tuple[StaticFinding | SemanticFinding, Fix]] = []

    # Process static findings, checking for duplicates with semantic
    for static_idx, sf in enumerate(static_findings):
        key = (sf.resource_logical_id, sf.pillar)
        static_fix_key = sf.rule_id if sf.rule_id else f"static_{static_idx}"
        static_fix = fixes.get(static_fix_key, Fix(description=""))

        matched = False
        if key in semantic_by_key:
            for sem_finding, sem_idx in semantic_by_key[key]:
                if sem_idx in matched_semantic_indices:
                    continue
                if _intents_match(sf.title, sem_finding.title):
                    # Duplicate detected: retain semantic, merge fixes
                    sem_fix_key = f"semantic_{sem_idx}"
                    sem_fix = fixes.get(sem_fix_key, Fix(description=sem_finding.suggested_fix))
                    merged_fix = _merge_fixes(static_fix, sem_fix)
                    result.append((sem_finding, merged_fix))
                    matched_semantic_indices.add(sem_idx)
                    matched = True
                    break

        if not matched:
            result.append((sf, static_fix))

    # Add remaining (unmatched) semantic findings
    for idx, sem_finding in enumerate(semantic_findings):
        if idx not in matched_semantic_indices:
            sem_fix_key = f"semantic_{idx}"
            sem_fix = fixes.get(sem_fix_key, Fix(description=sem_finding.suggested_fix))
            result.append((sem_finding, sem_fix))

    return result


def compose_response(
    static_findings: list[StaticFinding],
    semantic_findings: list[SemanticFinding],
    fixes: dict[str, Fix],
    graph: ResourceGraph,
    passed_checks: int,
    semantic_unavailable: bool = False,
    memory_unavailable: bool = False,
) -> ReviewResponse:
    """Compose the final review response.

    Deduplicates findings (same resource + same pillar + same intent),
    sorts by severity then alphabetical resource ID,
    assigns sequential IDs (F001, F002, ...).
    """
    # Step 1: Deduplicate findings
    deduped = _deduplicate(static_findings, semantic_findings, fixes)

    # Step 2: Sort findings by severity (critical > warning > info),
    # then alphabetical by resource logical ID
    deduped.sort(
        key=lambda item: (
            _SEVERITY_ORDER.get(item[0].severity, 99),
            item[0].resource_logical_id,
        )
    )

    # Step 3: Build Finding objects with resource display and sequential IDs
    composed_findings: list[Finding] = []
    for idx, (raw_finding, fix) in enumerate(deduped, start=1):
        finding_id = f"F{idx:03d}"
        resource_display = _resource_display(raw_finding.resource_logical_id, graph)

        composed_findings.append(
            Finding(
                id=finding_id,
                severity=raw_finding.severity,
                pillar=raw_finding.pillar,
                resource=resource_display,
                title=raw_finding.title,
                description=raw_finding.description,
                source=raw_finding.source,
                fix=fix,
            )
        )

    # Step 4: Handle semantic_unavailable flag
    if semantic_unavailable:
        composed_findings.append(
            Finding(
                id=f"F{len(composed_findings) + 1:03d}",
                severity="info",
                pillar="operational_excellence",
                resource="",
                title="Semantic analysis unavailable",
                description=(
                    "Semantic analysis was unavailable for this review. "
                    "Results contain static analysis only."
                ),
                source="semantic",
                fix=Fix(description=""),
            )
        )

    # Step 5: Handle memory_unavailable flag
    if memory_unavailable:
        composed_findings.append(
            Finding(
                id=f"F{len(composed_findings) + 1:03d}",
                severity="info",
                pillar="operational_excellence",
                resource="",
                title="Organization rules could not be loaded",
                description=(
                    "Organization rules could not be loaded. "
                    "Review uses built-in rules only."
                ),
                source="org_rule",
                fix=Fix(description=""),
            )
        )

    # Step 6: Compute summary
    critical_count = sum(1 for f in composed_findings if f.severity == "critical")
    warning_count = sum(1 for f in composed_findings if f.severity == "warning")
    info_count = sum(1 for f in composed_findings if f.severity == "info")

    summary = ReviewSummary(
        total_resources=len(graph.nodes),
        total_findings=len(composed_findings),
        critical=critical_count,
        warning=warning_count,
        info=info_count,
        passed_checks=passed_checks,
    )

    return ReviewResponse(summary=summary, findings=composed_findings)

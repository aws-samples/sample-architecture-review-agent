"""Organization-specific rules manager for the Architecture Review Agent.

Manages CRUD operations for organization rules, persisted via a MemoryStore
abstraction. Uses AgentCore Memory in production and InMemoryStore for testing.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Protocol

from src.models import (
    OrgRule,
    OrgRuleLimitError,
    OrgRuleNotFoundError,
    OrgRuleValidationError,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_SEVERITIES = frozenset({"critical", "warning", "info"})

VALID_PILLARS = frozenset({
    "security",
    "reliability",
    "performance_efficiency",
    "cost_optimization",
    "operational_excellence",
    "sustainability",
})

MAX_RULES_PER_ORG = 200
MAX_RULE_TEXT_LENGTH = 500


# ---------------------------------------------------------------------------
# Memory Store Protocol
# ---------------------------------------------------------------------------


class MemoryStore(Protocol):
    """Abstract interface for memory persistence."""

    def store_record(self, namespace: str, record_id: str, content: dict[str, Any]) -> None:
        """Store a record under the given namespace with a unique ID."""
        ...

    def list_records(self, namespace: str) -> list[dict[str, Any]]:
        """List all records under the given namespace."""
        ...

    def delete_record(self, namespace: str, record_id: str) -> bool:
        """Delete a record by ID. Returns True if deleted, False if not found."""
        ...


# ---------------------------------------------------------------------------
# In-Memory Store (for testing)
# ---------------------------------------------------------------------------


class InMemoryStore:
    """In-memory implementation of MemoryStore for unit testing."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, dict[str, Any]]] = {}

    def store_record(self, namespace: str, record_id: str, content: dict[str, Any]) -> None:
        """Store a record under the given namespace."""
        if namespace not in self._store:
            self._store[namespace] = {}
        self._store[namespace][record_id] = content

    def list_records(self, namespace: str) -> list[dict[str, Any]]:
        """List all records under the given namespace."""
        if namespace not in self._store:
            return []
        return list(self._store[namespace].values())

    def delete_record(self, namespace: str, record_id: str) -> bool:
        """Delete a record by ID. Returns True if deleted, False if not found."""
        if namespace not in self._store:
            return False
        if record_id not in self._store[namespace]:
            return False
        del self._store[namespace][record_id]
        return True


# ---------------------------------------------------------------------------
# Org Rules Manager
# ---------------------------------------------------------------------------


class OrgRulesManager:
    """Manages organization-specific rules in AgentCore Memory."""

    def __init__(self, memory_store: MemoryStore | None = None) -> None:
        """Initialize with optional memory store (for testing with mocks).

        Args:
            memory_store: A MemoryStore implementation. Defaults to InMemoryStore
                         if not provided.
        """
        self._store: MemoryStore = memory_store if memory_store is not None else InMemoryStore()

    def _namespace(self, org_id: str) -> str:
        """Build the memory namespace for an organization's rules."""
        return f"/org/{org_id}/rules/"

    def _validate_rule_text(self, rule_text: str) -> None:
        """Validate rule text is non-empty and within length limits."""
        if not rule_text or len(rule_text.strip()) == 0:
            raise OrgRuleValidationError("rule_text", "must not be empty")
        if len(rule_text) > MAX_RULE_TEXT_LENGTH:
            raise OrgRuleValidationError(
                "rule_text",
                f"must not exceed {MAX_RULE_TEXT_LENGTH} characters (got {len(rule_text)})",
            )

    def _validate_severity(self, severity: str) -> None:
        """Validate severity is one of the allowed values."""
        if severity not in VALID_SEVERITIES:
            valid = ", ".join(sorted(VALID_SEVERITIES))
            raise OrgRuleValidationError(
                "severity",
                f"must be one of: {valid} (got '{severity}')",
            )

    def _validate_pillar(self, pillar: str | None) -> None:
        """Validate pillar is one of the allowed values if provided."""
        if pillar is not None and pillar not in VALID_PILLARS:
            valid = ", ".join(sorted(VALID_PILLARS))
            raise OrgRuleValidationError(
                "pillar",
                f"must be one of: {valid} (got '{pillar}')",
            )

    def add_org_rule(
        self,
        rule_text: str,
        severity: str,
        pillar: str | None = None,
        org_id: str = "",
    ) -> OrgRule:
        """Add a new organization rule.

        Validates inputs, generates a UUID rule_id, and persists to memory.
        Maximum 200 rules per organization enforced.

        Args:
            rule_text: Rule description (1-500 characters).
            severity: One of "critical", "warning", "info".
            pillar: Optional Well-Architected pillar association.
            org_id: Organization identity from OAuth2 token claims.

        Returns:
            The created OrgRule with generated rule_id and timestamp.

        Raises:
            OrgRuleValidationError: If inputs are invalid.
            OrgRuleLimitError: If 200 rules already exist for the org.
        """
        # Validate inputs
        self._validate_rule_text(rule_text)
        self._validate_severity(severity)
        self._validate_pillar(pillar)

        namespace = self._namespace(org_id)

        # Check rule count limit
        existing_rules = self._store.list_records(namespace)
        if len(existing_rules) >= MAX_RULES_PER_ORG:
            raise OrgRuleLimitError()

        # Generate rule
        rule_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        rule = OrgRule(
            rule_id=rule_id,
            rule_text=rule_text,
            severity=severity,
            pillar=pillar,
            created_at=created_at,
            org_id=org_id,
        )

        # Persist to memory store
        record_content = {
            "rule_id": rule.rule_id,
            "rule_text": rule.rule_text,
            "severity": rule.severity,
            "pillar": rule.pillar,
            "created_at": rule.created_at,
            "org_id": rule.org_id,
        }
        self._store.store_record(namespace, rule_id, record_content)

        return rule

    def get_org_rules(self, org_id: str) -> list[OrgRule]:
        """Retrieve all organization rules for the specified org.

        Args:
            org_id: Organization identity from OAuth2 token claims.

        Returns:
            List of OrgRule objects for the organization.
        """
        namespace = self._namespace(org_id)
        records = self._store.list_records(namespace)

        rules = []
        for record in records:
            rule = OrgRule(
                rule_id=record["rule_id"],
                rule_text=record["rule_text"],
                severity=record["severity"],
                pillar=record.get("pillar"),
                created_at=record.get("created_at", ""),
                org_id=record.get("org_id", org_id),
            )
            rules.append(rule)

        return rules

    def remove_org_rule(self, rule_id: str, org_id: str) -> dict:
        """Remove an organization rule by ID.

        Args:
            rule_id: The UUID of the rule to remove.
            org_id: Organization identity from OAuth2 token claims.

        Returns:
            Dict with the deleted rule_id confirmation.

        Raises:
            OrgRuleNotFoundError: If rule_id doesn't exist for the org.
        """
        namespace = self._namespace(org_id)
        deleted = self._store.delete_record(namespace, rule_id)

        if not deleted:
            raise OrgRuleNotFoundError(rule_id)

        return {"rule_id": rule_id, "status": "deleted"}

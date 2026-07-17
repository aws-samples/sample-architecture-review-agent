"""Unit tests for the Organization Rules Manager.

Tests CRUD operations, validation, and limit enforcement using InMemoryStore.
"""

import uuid
from datetime import datetime, timezone

import pytest

from src.models import (
    OrgRule,
    OrgRuleLimitError,
    OrgRuleNotFoundError,
    OrgRuleValidationError,
)
from src.org_rules import (
    InMemoryStore,
    MAX_RULE_TEXT_LENGTH,
    MAX_RULES_PER_ORG,
    OrgRulesManager,
    VALID_PILLARS,
    VALID_SEVERITIES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store():
    """Create a fresh InMemoryStore for each test."""
    return InMemoryStore()


@pytest.fixture
def manager(store):
    """Create an OrgRulesManager backed by an InMemoryStore."""
    return OrgRulesManager(memory_store=store)


@pytest.fixture
def org_id():
    """Default test organization ID."""
    return "test-org-123"


# ---------------------------------------------------------------------------
# InMemoryStore Tests
# ---------------------------------------------------------------------------


class TestInMemoryStore:
    """Tests for the InMemoryStore implementation."""

    def test_store_and_list(self):
        store = InMemoryStore()
        store.store_record("/ns/", "id1", {"key": "value1"})
        store.store_record("/ns/", "id2", {"key": "value2"})

        records = store.list_records("/ns/")
        assert len(records) == 2

    def test_list_empty_namespace(self):
        store = InMemoryStore()
        records = store.list_records("/nonexistent/")
        assert records == []

    def test_delete_existing_record(self):
        store = InMemoryStore()
        store.store_record("/ns/", "id1", {"key": "value"})

        result = store.delete_record("/ns/", "id1")
        assert result is True
        assert store.list_records("/ns/") == []

    def test_delete_nonexistent_record(self):
        store = InMemoryStore()
        result = store.delete_record("/ns/", "nonexistent")
        assert result is False

    def test_delete_from_nonexistent_namespace(self):
        store = InMemoryStore()
        result = store.delete_record("/nonexistent/", "id1")
        assert result is False

    def test_namespaces_are_isolated(self):
        store = InMemoryStore()
        store.store_record("/ns1/", "id1", {"key": "value1"})
        store.store_record("/ns2/", "id2", {"key": "value2"})

        assert len(store.list_records("/ns1/")) == 1
        assert len(store.list_records("/ns2/")) == 1


# ---------------------------------------------------------------------------
# add_org_rule Tests
# ---------------------------------------------------------------------------


class TestAddOrgRule:
    """Tests for OrgRulesManager.add_org_rule."""

    def test_add_valid_rule_minimal(self, manager, org_id):
        """Add a rule with required fields only."""
        rule = manager.add_org_rule(
            rule_text="All Lambda functions must have timeout set",
            severity="warning",
            org_id=org_id,
        )

        assert rule.rule_text == "All Lambda functions must have timeout set"
        assert rule.severity == "warning"
        assert rule.pillar is None
        assert rule.org_id == org_id
        assert rule.rule_id != ""
        assert rule.created_at != ""
        # Verify it's a valid UUID
        uuid.UUID(rule.rule_id)

    def test_add_valid_rule_with_pillar(self, manager, org_id):
        """Add a rule with optional pillar."""
        rule = manager.add_org_rule(
            rule_text="S3 buckets must have encryption enabled",
            severity="critical",
            pillar="security",
            org_id=org_id,
        )

        assert rule.pillar == "security"
        assert rule.severity == "critical"

    def test_add_rule_generates_uuid(self, manager, org_id):
        """rule_id should be a valid UUID4."""
        rule = manager.add_org_rule(
            rule_text="Test rule",
            severity="info",
            org_id=org_id,
        )

        parsed_uuid = uuid.UUID(rule.rule_id)
        assert parsed_uuid.version == 4

    def test_add_rule_generates_iso_timestamp(self, manager, org_id):
        """created_at should be a valid ISO 8601 timestamp."""
        rule = manager.add_org_rule(
            rule_text="Test rule",
            severity="info",
            org_id=org_id,
        )

        # Should parse without error
        dt = datetime.fromisoformat(rule.created_at)
        assert dt.tzinfo is not None  # Should have timezone info

    def test_add_rule_persists_to_store(self, manager, org_id):
        """Added rule should be retrievable via get_org_rules."""
        manager.add_org_rule(
            rule_text="Test rule",
            severity="warning",
            org_id=org_id,
        )

        rules = manager.get_org_rules(org_id)
        assert len(rules) == 1
        assert rules[0].rule_text == "Test rule"

    def test_add_multiple_rules(self, manager, org_id):
        """Multiple rules can be added and retrieved."""
        manager.add_org_rule(rule_text="Rule 1", severity="critical", org_id=org_id)
        manager.add_org_rule(rule_text="Rule 2", severity="warning", org_id=org_id)
        manager.add_org_rule(rule_text="Rule 3", severity="info", org_id=org_id)

        rules = manager.get_org_rules(org_id)
        assert len(rules) == 3

    def test_add_rule_all_valid_severities(self, manager, org_id):
        """All three severity values are accepted."""
        for severity in VALID_SEVERITIES:
            rule = manager.add_org_rule(
                rule_text=f"Rule for {severity}",
                severity=severity,
                org_id=org_id,
            )
            assert rule.severity == severity

    def test_add_rule_all_valid_pillars(self, manager, org_id):
        """All six pillar values are accepted."""
        for pillar in VALID_PILLARS:
            rule = manager.add_org_rule(
                rule_text=f"Rule for {pillar}",
                severity="info",
                pillar=pillar,
                org_id=org_id,
            )
            assert rule.pillar == pillar

    def test_add_rule_max_length_text(self, manager, org_id):
        """Rule text at exactly 500 chars should succeed."""
        rule_text = "x" * MAX_RULE_TEXT_LENGTH
        rule = manager.add_org_rule(
            rule_text=rule_text,
            severity="info",
            org_id=org_id,
        )
        assert len(rule.rule_text) == MAX_RULE_TEXT_LENGTH

    def test_add_rule_single_char_text(self, manager, org_id):
        """Rule text with single char should succeed."""
        rule = manager.add_org_rule(
            rule_text="x",
            severity="info",
            org_id=org_id,
        )
        assert rule.rule_text == "x"


# ---------------------------------------------------------------------------
# Validation Error Tests
# ---------------------------------------------------------------------------


class TestAddOrgRuleValidation:
    """Tests for input validation in add_org_rule."""

    def test_empty_rule_text_raises(self, manager, org_id):
        """Empty rule text should raise OrgRuleValidationError."""
        with pytest.raises(OrgRuleValidationError) as exc_info:
            manager.add_org_rule(rule_text="", severity="info", org_id=org_id)
        assert exc_info.value.field_name == "rule_text"

    def test_whitespace_only_rule_text_raises(self, manager, org_id):
        """Whitespace-only rule text should raise OrgRuleValidationError."""
        with pytest.raises(OrgRuleValidationError) as exc_info:
            manager.add_org_rule(rule_text="   ", severity="info", org_id=org_id)
        assert exc_info.value.field_name == "rule_text"

    def test_rule_text_exceeds_500_chars_raises(self, manager, org_id):
        """Rule text over 500 chars should raise OrgRuleValidationError."""
        long_text = "x" * (MAX_RULE_TEXT_LENGTH + 1)
        with pytest.raises(OrgRuleValidationError) as exc_info:
            manager.add_org_rule(rule_text=long_text, severity="info", org_id=org_id)
        assert exc_info.value.field_name == "rule_text"

    def test_invalid_severity_raises(self, manager, org_id):
        """Invalid severity value should raise OrgRuleValidationError."""
        with pytest.raises(OrgRuleValidationError) as exc_info:
            manager.add_org_rule(rule_text="Test rule", severity="high", org_id=org_id)
        assert exc_info.value.field_name == "severity"

    def test_invalid_pillar_raises(self, manager, org_id):
        """Invalid pillar value should raise OrgRuleValidationError."""
        with pytest.raises(OrgRuleValidationError) as exc_info:
            manager.add_org_rule(
                rule_text="Test rule",
                severity="info",
                pillar="invalid_pillar",
                org_id=org_id,
            )
        assert exc_info.value.field_name == "pillar"

    def test_none_pillar_is_valid(self, manager, org_id):
        """None pillar should not raise an error."""
        rule = manager.add_org_rule(
            rule_text="Test rule",
            severity="info",
            pillar=None,
            org_id=org_id,
        )
        assert rule.pillar is None

    def test_invalid_rule_not_persisted(self, manager, org_id):
        """Invalid rules should not appear in get_org_rules."""
        with pytest.raises(OrgRuleValidationError):
            manager.add_org_rule(rule_text="", severity="info", org_id=org_id)

        rules = manager.get_org_rules(org_id)
        assert len(rules) == 0


# ---------------------------------------------------------------------------
# Rule Limit Tests
# ---------------------------------------------------------------------------


class TestOrgRuleLimit:
    """Tests for the 200 rule limit enforcement."""

    def test_limit_enforcement(self, manager, org_id):
        """Adding 201st rule should raise OrgRuleLimitError."""
        # Add 200 rules
        for i in range(MAX_RULES_PER_ORG):
            manager.add_org_rule(
                rule_text=f"Rule {i}",
                severity="info",
                org_id=org_id,
            )

        # 201st should fail
        with pytest.raises(OrgRuleLimitError):
            manager.add_org_rule(
                rule_text="One too many",
                severity="info",
                org_id=org_id,
            )

    def test_limit_not_persisted_on_error(self, manager, org_id):
        """Rule exceeding limit should not be persisted."""
        for i in range(MAX_RULES_PER_ORG):
            manager.add_org_rule(
                rule_text=f"Rule {i}",
                severity="info",
                org_id=org_id,
            )

        with pytest.raises(OrgRuleLimitError):
            manager.add_org_rule(
                rule_text="Should not persist",
                severity="info",
                org_id=org_id,
            )

        rules = manager.get_org_rules(org_id)
        assert len(rules) == MAX_RULES_PER_ORG

    def test_can_add_after_removing_at_limit(self, manager, org_id):
        """Removing a rule at limit should allow adding a new one."""
        for i in range(MAX_RULES_PER_ORG):
            manager.add_org_rule(
                rule_text=f"Rule {i}",
                severity="info",
                org_id=org_id,
            )

        # Remove one rule
        rules = manager.get_org_rules(org_id)
        manager.remove_org_rule(rules[0].rule_id, org_id)

        # Should now succeed
        rule = manager.add_org_rule(
            rule_text="New rule after removal",
            severity="info",
            org_id=org_id,
        )
        assert rule.rule_text == "New rule after removal"


# ---------------------------------------------------------------------------
# get_org_rules Tests
# ---------------------------------------------------------------------------


class TestGetOrgRules:
    """Tests for OrgRulesManager.get_org_rules."""

    def test_get_empty_org(self, manager, org_id):
        """Getting rules for org with none should return empty list."""
        rules = manager.get_org_rules(org_id)
        assert rules == []

    def test_get_returns_all_fields(self, manager, org_id):
        """Retrieved rules should have all fields populated."""
        manager.add_org_rule(
            rule_text="Full rule",
            severity="critical",
            pillar="security",
            org_id=org_id,
        )

        rules = manager.get_org_rules(org_id)
        assert len(rules) == 1

        rule = rules[0]
        assert rule.rule_text == "Full rule"
        assert rule.severity == "critical"
        assert rule.pillar == "security"
        assert rule.org_id == org_id
        assert rule.rule_id != ""
        assert rule.created_at != ""

    def test_org_isolation(self, manager):
        """Rules from one org should not be visible to another."""
        manager.add_org_rule(
            rule_text="Org A rule",
            severity="info",
            org_id="org-a",
        )
        manager.add_org_rule(
            rule_text="Org B rule",
            severity="info",
            org_id="org-b",
        )

        org_a_rules = manager.get_org_rules("org-a")
        org_b_rules = manager.get_org_rules("org-b")

        assert len(org_a_rules) == 1
        assert org_a_rules[0].rule_text == "Org A rule"

        assert len(org_b_rules) == 1
        assert org_b_rules[0].rule_text == "Org B rule"


# ---------------------------------------------------------------------------
# remove_org_rule Tests
# ---------------------------------------------------------------------------


class TestRemoveOrgRule:
    """Tests for OrgRulesManager.remove_org_rule."""

    def test_remove_existing_rule(self, manager, org_id):
        """Removing an existing rule should succeed and return confirmation."""
        rule = manager.add_org_rule(
            rule_text="To be removed",
            severity="info",
            org_id=org_id,
        )

        result = manager.remove_org_rule(rule.rule_id, org_id)
        assert result["rule_id"] == rule.rule_id
        assert result["status"] == "deleted"

    def test_remove_rule_not_in_get(self, manager, org_id):
        """Removed rule should not appear in subsequent get_org_rules."""
        rule = manager.add_org_rule(
            rule_text="To be removed",
            severity="info",
            org_id=org_id,
        )

        manager.remove_org_rule(rule.rule_id, org_id)
        rules = manager.get_org_rules(org_id)
        assert len(rules) == 0

    def test_remove_nonexistent_rule_raises(self, manager, org_id):
        """Removing a non-existent rule should raise OrgRuleNotFoundError."""
        with pytest.raises(OrgRuleNotFoundError) as exc_info:
            manager.remove_org_rule("nonexistent-id", org_id)
        assert exc_info.value.rule_id == "nonexistent-id"

    def test_remove_rule_from_wrong_org_raises(self, manager):
        """Removing a rule from a different org should raise OrgRuleNotFoundError."""
        rule = manager.add_org_rule(
            rule_text="Org A rule",
            severity="info",
            org_id="org-a",
        )

        # Try removing from org-b (should fail)
        with pytest.raises(OrgRuleNotFoundError):
            manager.remove_org_rule(rule.rule_id, "org-b")

        # Original still exists
        rules = manager.get_org_rules("org-a")
        assert len(rules) == 1

    def test_remove_only_targeted_rule(self, manager, org_id):
        """Removing one rule should not affect others."""
        rule1 = manager.add_org_rule(rule_text="Rule 1", severity="info", org_id=org_id)
        rule2 = manager.add_org_rule(rule_text="Rule 2", severity="warning", org_id=org_id)

        manager.remove_org_rule(rule1.rule_id, org_id)

        rules = manager.get_org_rules(org_id)
        assert len(rules) == 1
        assert rules[0].rule_id == rule2.rule_id

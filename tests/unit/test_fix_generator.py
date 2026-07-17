"""Unit tests for the fix generator module.

Tests that fixes are generated correctly for static and semantic findings,
output format matches input template format, manual fixes produce code=None,
and resource context is properly referenced.
"""

from __future__ import annotations

import json

import yaml

from src.fix_generator import generate_fixes
from src.models import (
    Fix,
    ResourceGraph,
    ResourceNode,
    Rule,
    SemanticFinding,
    StaticFinding,
)


# ---------------------------------------------------------------------------
# Helper functions for building test data
# ---------------------------------------------------------------------------


def _make_graph(nodes: list[ResourceNode] | None = None) -> ResourceGraph:
    """Create a ResourceGraph with the given nodes."""
    return ResourceGraph(
        nodes=nodes or [],
        edges=[],
        patterns=[],
        template_format="yaml",
    )


def _make_s3_node(
    logical_id: str = "MyBucket", properties: dict | None = None
) -> ResourceNode:
    """Create an S3 bucket resource node."""
    return ResourceNode(
        logical_id=logical_id,
        resource_type="AWS::S3::Bucket",
        properties=properties or {"BucketName": "my-app-bucket"},
    )


def _make_dynamodb_node(
    logical_id: str = "AppTable", properties: dict | None = None
) -> ResourceNode:
    """Create a DynamoDB table resource node."""
    return ResourceNode(
        logical_id=logical_id,
        resource_type="AWS::DynamoDB::Table",
        properties=properties
        or {
            "TableName": "app-table",
            "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
            "AttributeDefinitions": [
                {"AttributeName": "id", "AttributeType": "S"}
            ],
        },
    )


def _make_rds_node(
    logical_id: str = "AppDatabase", properties: dict | None = None
) -> ResourceNode:
    """Create an RDS instance resource node."""
    return ResourceNode(
        logical_id=logical_id,
        resource_type="AWS::RDS::DBInstance",
        properties=properties
        or {
            "DBInstanceClass": "db.t3.micro",
            "Engine": "postgres",
        },
    )


def _make_rule(
    rule_id: str = "SEC-004",
    fix_hint: str = "Add BucketEncryption with ServerSideEncryptionByDefault using 'aws:kms' or 'AES256'",
) -> Rule:
    """Create a test Rule with the given fix_hint."""
    return Rule(
        id=rule_id,
        pillar="security",
        category="Data Protection",
        principle="Protect data at rest",
        title="S3 bucket without encryption",
        description="S3 buckets should have encryption enabled.",
        severity="critical",
        resource_types=["AWS::S3::Bucket"],
        check="BucketEncryption",
        fix_hint=fix_hint,
    )


# ---------------------------------------------------------------------------
# Tests: Static finding fix generation
# ---------------------------------------------------------------------------


class TestStaticFixGeneration:
    """Tests for generating fixes from static findings."""

    def test_s3_encryption_fix_yaml(self):
        """Static finding for S3 encryption produces YAML code fix."""
        node = _make_s3_node()
        graph = _make_graph([node])
        rule = _make_rule("SEC-004")
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="S3 bucket without encryption",
            description="S3 buckets should have encryption enabled.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        assert "SEC-004" in fixes
        fix = fixes["SEC-004"]
        assert fix.code is not None
        # Should be valid YAML
        parsed = yaml.safe_load(fix.code)
        assert "MyBucket" in parsed
        assert "Properties" in parsed["MyBucket"]
        props = parsed["MyBucket"]["Properties"]
        assert "BucketEncryption" in props

    def test_s3_encryption_fix_json(self):
        """Static finding for S3 encryption produces JSON code fix."""
        node = _make_s3_node()
        graph = _make_graph([node])
        rule = _make_rule("SEC-004")
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="S3 bucket without encryption",
            description="S3 buckets should have encryption enabled.",
        )

        fixes = generate_fixes([finding], graph, "json", rules=[rule])

        assert "SEC-004" in fixes
        fix = fixes["SEC-004"]
        assert fix.code is not None
        # Should be valid JSON
        parsed = json.loads(fix.code)
        assert "MyBucket" in parsed
        assert "Properties" in parsed["MyBucket"]
        props = parsed["MyBucket"]["Properties"]
        assert "BucketEncryption" in props

    def test_dynamodb_encryption_fix(self):
        """Static finding for DynamoDB encryption produces correct fix."""
        node = _make_dynamodb_node()
        graph = _make_graph([node])
        rule = _make_rule(
            "SEC-005",
            "Add SSESpecification with SSEEnabled: true and SSEType: 'KMS'",
        )
        finding = StaticFinding(
            rule_id="SEC-005",
            severity="warning",
            pillar="security",
            resource_logical_id="AppTable",
            title="DynamoDB table without encryption",
            description="DynamoDB tables should use KMS encryption.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        assert "SEC-005" in fixes
        fix = fixes["SEC-005"]
        assert fix.code is not None
        parsed = yaml.safe_load(fix.code)
        assert "AppTable" in parsed
        props = parsed["AppTable"]["Properties"]
        assert "SSESpecification" in props
        assert props["SSESpecification"]["SSEEnabled"] is True

    def test_rds_encryption_fix(self):
        """Static finding for RDS encryption produces correct fix."""
        node = _make_rds_node()
        graph = _make_graph([node])
        rule = _make_rule(
            "SEC-007",
            "Set StorageEncrypted: true. Note: requires instance recreation for existing unencrypted DBs.",
        )
        finding = StaticFinding(
            rule_id="SEC-007",
            severity="critical",
            pillar="security",
            resource_logical_id="AppDatabase",
            title="RDS instance without encryption",
            description="RDS should have storage encryption.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        assert "SEC-007" in fixes
        fix = fixes["SEC-007"]
        assert fix.code is not None
        parsed = yaml.safe_load(fix.code)
        assert "AppDatabase" in parsed
        props = parsed["AppDatabase"]["Properties"]
        assert props["StorageEncrypted"] is True

    def test_fix_references_existing_logical_id(self):
        """Fix code uses the actual logical ID from the template."""
        node = _make_s3_node(logical_id="ProductionDataBucket")
        graph = _make_graph([node])
        rule = _make_rule("SEC-004")
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="ProductionDataBucket",
            title="S3 bucket without encryption",
            description="S3 buckets should have encryption enabled.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        fix = fixes["SEC-004"]
        assert fix.code is not None
        parsed = yaml.safe_load(fix.code)
        assert "ProductionDataBucket" in parsed
        # Should NOT contain a generic name
        assert "MyBucket" not in parsed

    def test_fix_preserves_existing_properties(self):
        """Fix includes existing properties alongside the new ones."""
        node = _make_s3_node(
            properties={"BucketName": "my-app-data", "Tags": [{"Key": "env", "Value": "prod"}]}
        )
        graph = _make_graph([node])
        rule = _make_rule("SEC-004")
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="S3 bucket without encryption",
            description="S3 buckets should have encryption enabled.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        fix = fixes["SEC-004"]
        assert fix.code is not None
        parsed = yaml.safe_load(fix.code)
        props = parsed["MyBucket"]["Properties"]
        # Should have the new encryption AND existing properties
        assert "BucketEncryption" in props
        assert props["BucketName"] == "my-app-data"

    def test_missing_resource_node_returns_none_code(self):
        """If the resource isn't in the graph, fix has code=None."""
        graph = _make_graph([])  # Empty graph
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="NonexistentBucket",
            title="S3 bucket without encryption",
            description="S3 buckets should have encryption enabled.",
        )

        fixes = generate_fixes([finding], graph, "yaml")

        fix = fixes["SEC-004"]
        assert fix.code is None
        assert fix.description != ""


# ---------------------------------------------------------------------------
# Tests: Semantic finding fix generation
# ---------------------------------------------------------------------------


class TestSemanticFixGeneration:
    """Tests for generating fixes from semantic findings."""

    def test_semantic_fix_with_encryption_suggestion(self):
        """Semantic finding with encryption suggested_fix produces code."""
        node = _make_s3_node()
        graph = _make_graph([node])
        finding = SemanticFinding(
            severity="warning",
            pillar="security",
            resource_logical_id="MyBucket",
            title="Unencrypted data store in payment pipeline",
            description="MyBucket stores payment data but lacks encryption.",
            suggested_fix="Enable server-side encryption on the S3 bucket",
        )

        fixes = generate_fixes([finding], graph, "yaml")

        assert "semantic-0" in fixes
        fix = fixes["semantic-0"]
        assert fix.code is not None
        parsed = yaml.safe_load(fix.code)
        assert "MyBucket" in parsed
        props = parsed["MyBucket"]["Properties"]
        assert "BucketEncryption" in props

    def test_semantic_fix_json_format(self):
        """Semantic finding generates JSON when input_format is json."""
        node = _make_s3_node()
        graph = _make_graph([node])
        finding = SemanticFinding(
            severity="warning",
            pillar="security",
            resource_logical_id="MyBucket",
            title="Unencrypted bucket",
            description="Enable encryption on MyBucket.",
            suggested_fix="Add encryption configuration to the S3 bucket",
        )

        fixes = generate_fixes([finding], graph, "json")

        fix = fixes["semantic-0"]
        assert fix.code is not None
        # Should be valid JSON
        parsed = json.loads(fix.code)
        assert "MyBucket" in parsed

    def test_semantic_fix_empty_suggested_fix(self):
        """Semantic finding with empty suggested_fix returns code=None."""
        node = _make_s3_node()
        graph = _make_graph([node])
        finding = SemanticFinding(
            severity="info",
            pillar="reliability",
            resource_logical_id="MyBucket",
            title="Architecture concern",
            description="Consider adding replication.",
            suggested_fix="",
        )

        fixes = generate_fixes([finding], graph, "yaml")

        fix = fixes["semantic-0"]
        assert fix.code is None
        assert fix.description == finding.description

    def test_semantic_fix_references_logical_id(self):
        """Semantic fix uses the correct logical ID from the graph."""
        node = _make_dynamodb_node(logical_id="OrdersTable")
        graph = _make_graph([node])
        finding = SemanticFinding(
            severity="warning",
            pillar="reliability",
            resource_logical_id="OrdersTable",
            title="No backup configured",
            description="OrdersTable has no backup retention policy.",
            suggested_fix="Enable backup and point-in-time recovery",
        )

        fixes = generate_fixes([finding], graph, "yaml")

        fix = fixes["semantic-0"]
        assert fix.code is not None
        parsed = yaml.safe_load(fix.code)
        assert "OrdersTable" in parsed

    def test_multiple_semantic_findings_indexed(self):
        """Multiple semantic findings get sequential index-based keys."""
        node1 = _make_s3_node(logical_id="Bucket1")
        node2 = _make_s3_node(logical_id="Bucket2")
        graph = _make_graph([node1, node2])

        findings = [
            SemanticFinding(
                severity="warning",
                pillar="security",
                resource_logical_id="Bucket1",
                title="Issue 1",
                description="First issue.",
                suggested_fix="Enable encryption on Bucket1",
            ),
            SemanticFinding(
                severity="info",
                pillar="security",
                resource_logical_id="Bucket2",
                title="Issue 2",
                description="Second issue.",
                suggested_fix="Enable versioning on Bucket2",
            ),
        ]

        fixes = generate_fixes(findings, graph, "yaml")

        assert "semantic-0" in fixes
        assert "semantic-1" in fixes


# ---------------------------------------------------------------------------
# Tests: Manual fix (code=None) generation
# ---------------------------------------------------------------------------


class TestManualFixGeneration:
    """Tests for findings that require manual decisions."""

    def test_manual_keyword_choose_between(self):
        """Finding with 'choose between' in fix returns code=None."""
        node = _make_s3_node()
        graph = _make_graph([node])
        rule = _make_rule(
            "SEC-099",
            "Choose between SSE-S3 and SSE-KMS based on compliance needs",
        )
        finding = StaticFinding(
            rule_id="SEC-099",
            severity="warning",
            pillar="security",
            resource_logical_id="MyBucket",
            title="Encryption type decision",
            description="Choose between SSE-S3 and SSE-KMS based on compliance needs",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        fix = fixes["SEC-099"]
        assert fix.code is None
        assert "choose between" in fix.description.lower()

    def test_manual_keyword_requires_external(self):
        """Finding with 'requires external' in fix returns code=None."""
        node = _make_rds_node()
        graph = _make_graph([node])
        rule = _make_rule(
            "SEC-100",
            "Requires external VPN or Direct Connect configuration",
        )
        finding = StaticFinding(
            rule_id="SEC-100",
            severity="critical",
            pillar="security",
            resource_logical_id="AppDatabase",
            title="Network access configuration",
            description="Requires external VPN or Direct Connect configuration",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        fix = fixes["SEC-100"]
        assert fix.code is None
        assert fix.description != ""

    def test_semantic_manual_fix(self):
        """Semantic finding with manual keyword in suggested_fix returns code=None."""
        node = _make_s3_node()
        graph = _make_graph([node])
        finding = SemanticFinding(
            severity="warning",
            pillar="operational_excellence",
            resource_logical_id="MyBucket",
            title="Architecture decision needed",
            description="Design choice required.",
            suggested_fix="Choose between active-active and active-passive architectural decision",
        )

        fixes = generate_fixes([finding], graph, "yaml")

        fix = fixes["semantic-0"]
        assert fix.code is None


# ---------------------------------------------------------------------------
# Tests: Format output correctness
# ---------------------------------------------------------------------------


class TestFormatOutput:
    """Tests that output format matches input_format parameter."""

    def test_yaml_output_is_valid_yaml(self):
        """When input_format='yaml', all code fixes are valid YAML."""
        node = _make_s3_node()
        graph = _make_graph([node])
        rule = _make_rule("SEC-004")
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="No encryption",
            description="Enable encryption.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        fix = fixes["SEC-004"]
        assert fix.code is not None
        # Should not raise
        parsed = yaml.safe_load(fix.code)
        assert isinstance(parsed, dict)

    def test_json_output_is_valid_json(self):
        """When input_format='json', all code fixes are valid JSON."""
        node = _make_s3_node()
        graph = _make_graph([node])
        rule = _make_rule("SEC-004")
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="No encryption",
            description="Enable encryption.",
        )

        fixes = generate_fixes([finding], graph, "json", rules=[rule])

        fix = fixes["SEC-004"]
        assert fix.code is not None
        # Should not raise
        parsed = json.loads(fix.code)
        assert isinstance(parsed, dict)

    def test_mixed_findings_all_same_format(self):
        """Both static and semantic findings use the same output format."""
        s3_node = _make_s3_node()
        dynamo_node = _make_dynamodb_node()
        graph = _make_graph([s3_node, dynamo_node])
        rule = _make_rule("SEC-004")

        findings: list[StaticFinding | SemanticFinding] = [
            StaticFinding(
                rule_id="SEC-004",
                severity="critical",
                pillar="security",
                resource_logical_id="MyBucket",
                title="No encryption",
                description="Enable encryption on S3.",
            ),
            SemanticFinding(
                severity="warning",
                pillar="reliability",
                resource_logical_id="AppTable",
                title="No backup",
                description="Enable backup on DynamoDB.",
                suggested_fix="Enable point-in-time backup and retention",
            ),
        ]

        fixes = generate_fixes(findings, graph, "json", rules=[rule])

        for key, fix in fixes.items():
            if fix.code is not None:
                # All should be valid JSON
                parsed = json.loads(fix.code)
                assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Tests: New resource additions (complete definitions)
# ---------------------------------------------------------------------------


class TestNewResourceAddition:
    """Tests for fixes that include complete resource definitions."""

    def test_fix_includes_complete_resource_definition(self):
        """Fix snippet includes Type and Properties for the resource."""
        node = _make_s3_node()
        graph = _make_graph([node])
        rule = _make_rule("SEC-004")
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="No encryption",
            description="Enable encryption.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        fix = fixes["SEC-004"]
        assert fix.code is not None
        parsed = yaml.safe_load(fix.code)
        resource = parsed["MyBucket"]
        assert "Type" in resource
        assert resource["Type"] == "AWS::S3::Bucket"
        assert "Properties" in resource


# ---------------------------------------------------------------------------
# Tests: Existing resource modifications (specific property changes)
# ---------------------------------------------------------------------------


class TestExistingResourceModification:
    """Tests for fixes that modify existing resources."""

    def test_fix_shows_specific_property_changes(self):
        """Fix includes the specific property that needs to be added."""
        node = _make_s3_node(properties={"BucketName": "data-bucket"})
        graph = _make_graph([node])
        rule = _make_rule("SEC-010", "Block all public access to the S3 bucket")
        finding = StaticFinding(
            rule_id="SEC-010",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="S3 bucket allows public access",
            description="Block public access on the bucket.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        fix = fixes["SEC-010"]
        assert fix.code is not None
        parsed = yaml.safe_load(fix.code)
        props = parsed["MyBucket"]["Properties"]
        assert "PublicAccessBlockConfiguration" in props
        pac = props["PublicAccessBlockConfiguration"]
        assert pac["BlockPublicAcls"] is True
        assert pac["BlockPublicPolicy"] is True
        assert pac["IgnorePublicAcls"] is True
        assert pac["RestrictPublicBuckets"] is True


# ---------------------------------------------------------------------------
# Tests: Fix with fix_hint from rules
# ---------------------------------------------------------------------------


class TestFixHintLookup:
    """Tests for fix_hint lookup from rules."""

    def test_uses_fix_hint_from_rule(self):
        """When rules are provided, fix uses the rule's fix_hint as description."""
        node = _make_s3_node()
        graph = _make_graph([node])
        rule = _make_rule(
            "SEC-004",
            "Add BucketEncryption with ServerSideEncryptionByDefault using 'aws:kms' or 'AES256'",
        )
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="No encryption",
            description="Generic description.",
        )

        fixes = generate_fixes([finding], graph, "yaml", rules=[rule])

        fix = fixes["SEC-004"]
        # Description should come from the fix_hint, not the generic description
        assert "BucketEncryption" in fix.description

    def test_falls_back_to_description_without_rules(self):
        """Without rules provided, fix falls back to finding description."""
        node = _make_s3_node()
        graph = _make_graph([node])
        finding = StaticFinding(
            rule_id="SEC-004",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="No encryption",
            description="S3 buckets should have encryption enabled.",
        )

        fixes = generate_fixes([finding], graph, "yaml")

        fix = fixes["SEC-004"]
        # Should use the finding description as the fix description
        assert "encryption" in fix.description.lower()

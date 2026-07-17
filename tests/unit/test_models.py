"""Unit tests for core data models."""

import pytest

from src.models import (
    ArchPattern,
    EmptyTemplateError,
    Finding,
    Fix,
    FormatMismatchError,
    InvalidFormatError,
    InvalidPillarError,
    OrgRule,
    OrgRuleLimitError,
    OrgRuleNotFoundError,
    OrgRuleValidationError,
    ParseError,
    ResourceEdge,
    ResourceGraph,
    ResourceLimitError,
    ResourceNode,
    ReviewResponse,
    ReviewSummary,
    Rule,
    SemanticFinding,
    StaticFinding,
)


class TestResourceNode:
    def test_creation(self):
        node = ResourceNode(
            logical_id="MyBucket",
            resource_type="AWS::S3::Bucket",
            properties={"BucketName": "my-bucket"},
        )
        assert node.logical_id == "MyBucket"
        assert node.resource_type == "AWS::S3::Bucket"
        assert node.properties == {"BucketName": "my-bucket"}

    def test_empty_properties(self):
        node = ResourceNode(logical_id="Fn", resource_type="AWS::Lambda::Function", properties={})
        assert node.properties == {}


class TestResourceEdge:
    def test_creation_with_attribute(self):
        edge = ResourceEdge(
            source="MyFunction",
            target="MyBucket",
            reference_type="Fn::GetAtt",
            attribute="Arn",
        )
        assert edge.source == "MyFunction"
        assert edge.target == "MyBucket"
        assert edge.reference_type == "Fn::GetAtt"
        assert edge.attribute == "Arn"

    def test_creation_without_attribute(self):
        edge = ResourceEdge(source="A", target="B", reference_type="Ref")
        assert edge.attribute is None


class TestArchPattern:
    def test_creation(self):
        pattern = ArchPattern(
            pattern_type="async_pipeline",
            resources=["MyQueue", "MyFunction"],
            description="SQS queue feeding a Lambda function",
        )
        assert pattern.pattern_type == "async_pipeline"
        assert pattern.resources == ["MyQueue", "MyFunction"]
        assert pattern.description == "SQS queue feeding a Lambda function"

    def test_defaults(self):
        pattern = ArchPattern(pattern_type="event_driven")
        assert pattern.resources == []
        assert pattern.description == ""


class TestResourceGraph:
    def test_defaults(self):
        graph = ResourceGraph()
        assert graph.nodes == []
        assert graph.edges == []
        assert graph.patterns == []
        assert graph.template_format == "yaml"

    def test_with_data(self):
        graph = ResourceGraph(
            nodes=[ResourceNode("A", "AWS::S3::Bucket", {})],
            edges=[ResourceEdge("A", "B", "Ref")],
            patterns=[ArchPattern("event_driven", ["A", "B"], "test")],
            template_format="json",
        )
        assert len(graph.nodes) == 1
        assert len(graph.edges) == 1
        assert len(graph.patterns) == 1
        assert graph.template_format == "json"


class TestRule:
    def test_creation(self):
        rule = Rule(
            id="SEC-001",
            pillar="security",
            category="encryption",
            principle="encrypt-at-rest",
            title="S3 Bucket Encryption",
            description="Ensure S3 bucket has encryption enabled",
            severity="critical",
            resource_types=["AWS::S3::Bucket"],
            check="properties.BucketEncryption",
            fix_hint="Add BucketEncryption property",
        )
        assert rule.id == "SEC-001"
        assert rule.severity == "critical"
        assert rule.resource_types == ["AWS::S3::Bucket"]

    def test_defaults(self):
        rule = Rule(
            id="R1", pillar="security", category="c", principle="p",
            title="t", description="d", severity="info",
        )
        assert rule.resource_types == []
        assert rule.check == ""
        assert rule.fix_hint == ""


class TestOrgRule:
    def test_creation(self):
        rule = OrgRule(
            rule_id="abc-123",
            rule_text="All Lambda functions must use Python 3.13",
            severity="warning",
            pillar="operational_excellence",
            created_at="2025-01-01T00:00:00Z",
            org_id="org-42",
        )
        assert rule.rule_id == "abc-123"
        assert rule.rule_text == "All Lambda functions must use Python 3.13"
        assert rule.severity == "warning"
        assert rule.pillar == "operational_excellence"

    def test_optional_fields(self):
        rule = OrgRule(rule_id="x", rule_text="test", severity="info")
        assert rule.pillar is None
        assert rule.created_at == ""
        assert rule.org_id == ""


class TestStaticFinding:
    def test_creation(self):
        finding = StaticFinding(
            rule_id="SEC-001",
            severity="critical",
            pillar="security",
            resource_logical_id="MyBucket",
            title="Missing encryption",
            description="S3 bucket does not have encryption enabled",
        )
        assert finding.source == "static"
        assert finding.rule_id == "SEC-001"

    def test_default_source(self):
        finding = StaticFinding("R1", "info", "security", "X", "T", "D")
        assert finding.source == "static"


class TestSemanticFinding:
    def test_creation(self):
        finding = SemanticFinding(
            severity="warning",
            pillar="reliability",
            resource_logical_id="MyQueue",
            title="No DLQ configured",
            description="MyQueue feeds MyFunction without error recovery",
            suggested_fix="Add a dead-letter queue to MyQueue",
        )
        assert finding.source == "semantic"
        assert finding.suggested_fix == "Add a dead-letter queue to MyQueue"

    def test_defaults(self):
        finding = SemanticFinding("info", "security", "X", "T", "D")
        assert finding.suggested_fix == ""
        assert finding.source == "semantic"


class TestFix:
    def test_with_code(self):
        fix = Fix(description="Add encryption", code="BucketEncryption:\n  ...")
        assert fix.code is not None

    def test_without_code(self):
        fix = Fix(description="Manual configuration required")
        assert fix.code is None


class TestFinding:
    def test_creation(self):
        finding = Finding(
            id="F001",
            severity="critical",
            pillar="security",
            resource="MyBucket (AWS::S3::Bucket)",
            title="Missing encryption",
            description="No encryption configured",
            source="static",
            fix=Fix(description="Enable encryption", code="..."),
            references=["https://docs.aws.amazon.com/..."],
        )
        assert finding.id == "F001"
        assert finding.source == "static"
        assert finding.fix.code == "..."
        assert len(finding.references) == 1

    def test_defaults(self):
        finding = Finding(
            id="F002", severity="info", pillar="cost_optimization",
            resource="X (AWS::Lambda::Function)", title="T",
            description="D", source="semantic",
        )
        assert finding.fix.description == ""
        assert finding.references == []


class TestReviewSummary:
    def test_defaults(self):
        summary = ReviewSummary()
        assert summary.total_resources == 0
        assert summary.total_findings == 0
        assert summary.critical == 0
        assert summary.warning == 0
        assert summary.info == 0
        assert summary.passed_checks == 0

    def test_with_values(self):
        summary = ReviewSummary(
            total_resources=10, total_findings=5,
            critical=1, warning=3, info=1, passed_checks=20,
        )
        assert summary.total_findings == summary.critical + summary.warning + summary.info


class TestReviewResponse:
    def test_defaults(self):
        response = ReviewResponse()
        assert response.summary.total_findings == 0
        assert response.findings == []

    def test_with_findings(self):
        finding = Finding(
            id="F001", severity="critical", pillar="security",
            resource="X (AWS::S3::Bucket)", title="T",
            description="D", source="static",
        )
        response = ReviewResponse(
            summary=ReviewSummary(total_resources=1, total_findings=1, critical=1),
            findings=[finding],
        )
        assert len(response.findings) == 1


class TestParseError:
    def test_attributes(self):
        err = ParseError(line_number=42, description="unexpected end of mapping")
        assert err.line_number == 42
        assert err.description == "unexpected end of mapping"
        assert "line 42" in str(err)
        assert "unexpected end of mapping" in str(err)

    def test_is_exception(self):
        assert issubclass(ParseError, Exception)


class TestEmptyTemplateError:
    def test_message(self):
        err = EmptyTemplateError()
        assert "no reviewable resources" in str(err)


class TestFormatMismatchError:
    def test_message(self):
        err = FormatMismatchError("terraform")
        assert err.declared_format == "terraform"
        assert "terraform" in str(err)


class TestInvalidFormatError:
    def test_message(self):
        err = InvalidFormatError("CloudFormation")
        assert err.format_value == "CloudFormation"
        assert "cloudformation" in str(err).lower() or "supported" in str(err)


class TestInvalidPillarError:
    def test_message(self):
        err = InvalidPillarError("invalid_pillar")
        assert err.value == "invalid_pillar"
        assert "invalid_pillar" in str(err)
        assert "security" in str(err)  # valid values listed

    def test_valid_pillars_constant(self):
        assert "security" in InvalidPillarError.VALID_PILLARS
        assert "reliability" in InvalidPillarError.VALID_PILLARS
        assert "performance_efficiency" in InvalidPillarError.VALID_PILLARS
        assert "cost_optimization" in InvalidPillarError.VALID_PILLARS
        assert "operational_excellence" in InvalidPillarError.VALID_PILLARS
        assert "sustainability" in InvalidPillarError.VALID_PILLARS
        assert len(InvalidPillarError.VALID_PILLARS) == 6


class TestOrgRuleValidationError:
    def test_message(self):
        err = OrgRuleValidationError("rule_text", "must not be empty")
        assert err.field_name == "rule_text"
        assert err.reason == "must not be empty"
        assert "rule_text" in str(err)
        assert "must not be empty" in str(err)


class TestOrgRuleNotFoundError:
    def test_message(self):
        err = OrgRuleNotFoundError("rule-xyz")
        assert err.rule_id == "rule-xyz"
        assert "rule-xyz" in str(err)


class TestOrgRuleLimitError:
    def test_message(self):
        err = OrgRuleLimitError()
        assert "200" in str(err)
        assert "Remove existing rules" in str(err)


class TestResourceLimitError:
    def test_message(self):
        err = ResourceLimitError()
        assert "200" in str(err)
        assert "exceeds" in str(err).lower() or "maximum" in str(err).lower()

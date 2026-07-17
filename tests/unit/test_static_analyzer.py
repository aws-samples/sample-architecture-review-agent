"""Unit tests for the static analysis engine."""

import json
import tempfile

import pytest

from src.models import (
    InvalidPillarError,
    ResourceGraph,
    ResourceNode,
    Rule,
    StaticFinding,
)
from src.static_analyzer import (
    _evaluate_check,
    _extract_property_path,
    _resolve_path,
    load_rules,
    run_static_analysis,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_graph(resources: list[tuple[str, str, dict]]) -> ResourceGraph:
    """Create a ResourceGraph from a list of (logical_id, type, properties) tuples."""
    nodes = [
        ResourceNode(logical_id=lid, resource_type=rtype, properties=props)
        for lid, rtype, props in resources
    ]
    return ResourceGraph(nodes=nodes, edges=[], patterns=[])


def _make_rule(
    rule_id: str = "TEST-001",
    pillar: str = "security",
    resource_types: list[str] | None = None,
    check: str = "BucketEncryption",
    severity: str = "critical",
) -> Rule:
    """Create a test rule with sensible defaults."""
    return Rule(
        id=rule_id,
        pillar=pillar,
        category="Test Category",
        principle="Test Principle",
        title=f"Test rule {rule_id}",
        description=f"Description for {rule_id}",
        severity=severity,
        resource_types=resource_types or ["AWS::S3::Bucket"],
        check=check,
        fix_hint="Fix it",
    )


# ---------------------------------------------------------------------------
# load_rules tests
# ---------------------------------------------------------------------------


class TestLoadRules:
    def test_loads_default_rules_file(self):
        """Should load all rules from the default wa_rules.json."""
        rules = load_rules()
        assert len(rules) >= 87  # At least the documented 87 rules

    def test_all_rules_have_required_fields(self):
        """Every loaded rule should have non-empty id, pillar, title."""
        rules = load_rules()
        for rule in rules:
            assert rule.id != ""
            assert rule.pillar != ""
            assert rule.title != ""
            assert rule.severity in ("critical", "warning", "info")
            assert len(rule.resource_types) > 0

    def test_loads_from_custom_path(self):
        """Should load rules from a custom file path."""
        custom_rules = {
            "metadata": {"total_rules": 1},
            "rules": [
                {
                    "id": "CUSTOM-001",
                    "pillar": "security",
                    "category": "Custom",
                    "principle": "Custom principle",
                    "title": "Custom rule",
                    "description": "A custom rule",
                    "severity": "warning",
                    "resource_types": ["AWS::S3::Bucket"],
                    "check": "BucketEncryption",
                    "fix_hint": "Fix it",
                }
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(custom_rules, f)
            f.flush()
            rules = load_rules(f.name)

        assert len(rules) == 1
        assert rules[0].id == "CUSTOM-001"
        assert rules[0].pillar == "security"

    def test_empty_rules_file(self):
        """Should handle a rules file with no rules gracefully."""
        custom_rules = {"metadata": {}, "rules": []}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(custom_rules, f)
            f.flush()
            rules = load_rules(f.name)

        assert rules == []


# ---------------------------------------------------------------------------
# _extract_property_path tests
# ---------------------------------------------------------------------------


class TestExtractPropertyPath:
    def test_simple_property(self):
        assert _extract_property_path("BucketEncryption") == "BucketEncryption"

    def test_dotted_path(self):
        assert (
            _extract_property_path("PublicAccessBlockConfiguration.BlockPublicAcls")
            == "PublicAccessBlockConfiguration.BlockPublicAcls"
        )

    def test_path_with_properties_prefix(self):
        assert (
            _extract_property_path("properties.BucketEncryption")
            == "BucketEncryption"
        )

    def test_path_with_array_notation(self):
        """Array brackets should be skipped but path segments preserved."""
        result = _extract_property_path("SecurityGroupIngress[].CidrIp")
        assert result == "SecurityGroupIngress.CidrIp"

    def test_complex_expression_extracts_first_path(self):
        """Complex check expressions should extract the leading path."""
        result = _extract_property_path(
            "BucketEncryption is not defined OR ServerSideEncryptionConfiguration is missing"
        )
        assert result == "BucketEncryption"

    def test_empty_check(self):
        assert _extract_property_path("") == ""


# ---------------------------------------------------------------------------
# _resolve_path tests
# ---------------------------------------------------------------------------


class TestResolvePath:
    def test_top_level_property_present_truthy(self):
        props = {"BucketEncryption": {"ServerSideEncryptionConfiguration": []}}
        assert _resolve_path("BucketEncryption", props) is True

    def test_top_level_property_missing(self):
        props = {"BucketName": "test"}
        assert _resolve_path("BucketEncryption", props) is False

    def test_nested_property_present(self):
        props = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
            }
        }
        assert (
            _resolve_path("PublicAccessBlockConfiguration.BlockPublicAcls", props)
            is True
        )

    def test_nested_property_missing_intermediate(self):
        props = {"SomethingElse": "value"}
        assert (
            _resolve_path("PublicAccessBlockConfiguration.BlockPublicAcls", props)
            is False
        )

    def test_nested_property_falsy_value(self):
        props = {"SSESpecification": {"SSEEnabled": False}}
        assert _resolve_path("SSESpecification.SSEEnabled", props) is False

    def test_nested_property_none_value(self):
        props = {"SSESpecification": {"SSEEnabled": None}}
        assert _resolve_path("SSESpecification.SSEEnabled", props) is False

    def test_empty_dict_is_falsy(self):
        props = {"BucketEncryption": {}}
        assert _resolve_path("BucketEncryption", props) is False

    def test_empty_list_is_falsy(self):
        props = {"Tags": []}
        assert _resolve_path("Tags", props) is False

    def test_nonempty_list_is_truthy(self):
        props = {"Tags": [{"Key": "env", "Value": "prod"}]}
        assert _resolve_path("Tags", props) is True

    def test_deep_nesting(self):
        props = {"A": {"B": {"C": {"D": "value"}}}}
        assert _resolve_path("A.B.C.D", props) is True

    def test_deep_nesting_missing_leaf(self):
        props = {"A": {"B": {"C": {}}}}
        assert _resolve_path("A.B.C.D", props) is False


# ---------------------------------------------------------------------------
# _evaluate_check tests
# ---------------------------------------------------------------------------


class TestEvaluateCheck:
    def test_empty_check_passes(self):
        """An empty check string should be treated as a pass."""
        assert _evaluate_check("", {}) is True

    def test_simple_property_present(self):
        props = {"BucketEncryption": {"Rules": [{"ServerSideEncryptionByDefault": {}}]}}
        assert _evaluate_check("BucketEncryption", props) is True

    def test_simple_property_missing(self):
        props = {"BucketName": "my-bucket"}
        assert _evaluate_check("BucketEncryption", props) is False

    def test_dotted_path_present(self):
        props = {"TracingConfig": {"Mode": "Active"}}
        assert _evaluate_check("TracingConfig.Mode", props) is True

    def test_dotted_path_missing(self):
        props = {"Runtime": "python3.13"}
        assert _evaluate_check("TracingConfig.Mode", props) is False


# ---------------------------------------------------------------------------
# run_static_analysis - rule-resource matching
# ---------------------------------------------------------------------------


class TestRuleResourceMatching:
    def test_rule_only_applies_to_matching_resource_types(self):
        """A rule targeting S3 buckets should not apply to Lambda functions."""
        graph = _make_graph([
            ("MyFunction", "AWS::Lambda::Function", {"Runtime": "python3.13"}),
        ])
        rule = _make_rule(resource_types=["AWS::S3::Bucket"], check="BucketEncryption")
        findings, passed = run_static_analysis(graph, [rule])
        assert findings == []
        assert passed == 0

    def test_rule_applies_to_matching_type(self):
        """A rule targeting S3 buckets should apply to an S3 bucket resource."""
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {"BucketEncryption": {"Rules": []}}),
        ])
        rule = _make_rule(resource_types=["AWS::S3::Bucket"], check="BucketEncryption")
        findings, passed = run_static_analysis(graph, [rule])
        # BucketEncryption is present but has empty list (falsy) → fails
        assert len(findings) == 0  # Wait - {"Rules": []} is truthy dict!
        # Actually the check resolves "BucketEncryption" → {"Rules": []} which is truthy
        assert passed == 1

    def test_resource_with_no_matching_rules_excluded(self):
        """Resources whose type doesn't match any rule should not appear in findings or passed."""
        graph = _make_graph([
            ("MyCustom", "AWS::CloudFormation::CustomResource", {"ServiceToken": "arn:..."}),
        ])
        rule = _make_rule(resource_types=["AWS::S3::Bucket"], check="BucketEncryption")
        findings, passed = run_static_analysis(graph, [rule])
        assert findings == []
        assert passed == 0

    def test_multiple_rules_for_same_resource(self):
        """Multiple applicable rules should each be evaluated."""
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {
                "BucketEncryption": {"ServerSideEncryptionConfiguration": [{}]},
            }),
        ])
        rules = [
            _make_rule(rule_id="R1", check="BucketEncryption"),  # passes
            _make_rule(rule_id="R2", check="VersioningConfiguration"),  # fails (missing)
        ]
        findings, passed = run_static_analysis(graph, rules)
        assert passed == 1
        assert len(findings) == 1
        assert findings[0].rule_id == "R2"

    def test_rule_with_multiple_resource_types(self):
        """A rule targeting multiple types should match any of them."""
        graph = _make_graph([
            ("MyVolume", "AWS::EC2::Volume", {"Encrypted": True}),
            ("MyInstance", "AWS::EC2::Instance", {}),
        ])
        rule = _make_rule(
            resource_types=["AWS::EC2::Volume", "AWS::EC2::Instance"],
            check="Encrypted",
        )
        findings, passed = run_static_analysis(graph, [rule])
        assert passed == 1  # Volume passes
        assert len(findings) == 1  # Instance fails (no Encrypted property)
        assert findings[0].resource_logical_id == "MyInstance"


# ---------------------------------------------------------------------------
# run_static_analysis - focus_pillars filtering
# ---------------------------------------------------------------------------


class TestFocusPillars:
    def test_focus_pillars_filters_rules(self):
        """Only rules matching the focus pillar should be evaluated."""
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {}),
        ])
        rules = [
            _make_rule(rule_id="SEC-1", pillar="security", check="BucketEncryption"),
            _make_rule(rule_id="REL-1", pillar="reliability", check="VersioningConfiguration"),
        ]
        findings, passed = run_static_analysis(
            graph, rules, focus_pillars=["security"]
        )
        # Only SEC-1 should be evaluated (fails because BucketEncryption missing)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-1"
        assert findings[0].pillar == "security"
        assert passed == 0

    def test_focus_pillars_multiple(self):
        """Multiple focus pillars should include rules from all specified pillars."""
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {}),
        ])
        rules = [
            _make_rule(rule_id="SEC-1", pillar="security", check="BucketEncryption"),
            _make_rule(rule_id="REL-1", pillar="reliability", check="VersioningConfiguration"),
            _make_rule(rule_id="COST-1", pillar="cost_optimization", check="IntelligentTieringConfiguration"),
        ]
        findings, passed = run_static_analysis(
            graph, rules, focus_pillars=["security", "reliability"]
        )
        assert len(findings) == 2
        pillar_ids = {f.rule_id for f in findings}
        assert pillar_ids == {"SEC-1", "REL-1"}

    def test_focus_pillars_none_evaluates_all(self):
        """When focus_pillars is None, all rules should be evaluated."""
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {}),
        ])
        rules = [
            _make_rule(rule_id="SEC-1", pillar="security", check="BucketEncryption"),
            _make_rule(rule_id="REL-1", pillar="reliability", check="VersioningConfiguration"),
        ]
        findings, passed = run_static_analysis(graph, rules, focus_pillars=None)
        assert len(findings) == 2

    def test_focus_pillars_empty_list_evaluates_none(self):
        """An empty focus_pillars list should result in no rules being evaluated."""
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {}),
        ])
        rules = [
            _make_rule(rule_id="SEC-1", pillar="security", check="BucketEncryption"),
        ]
        findings, passed = run_static_analysis(graph, rules, focus_pillars=[])
        assert findings == []
        assert passed == 0

    def test_invalid_pillar_raises_error(self):
        """Invalid pillar values should raise InvalidPillarError."""
        graph = _make_graph([])
        rules = []
        with pytest.raises(InvalidPillarError) as exc_info:
            run_static_analysis(graph, rules, focus_pillars=["invalid_pillar"])
        assert exc_info.value.value == "invalid_pillar"

    def test_invalid_pillar_mixed_with_valid(self):
        """Even one invalid pillar among valid ones should raise."""
        graph = _make_graph([])
        rules = []
        with pytest.raises(InvalidPillarError):
            run_static_analysis(
                graph, rules, focus_pillars=["security", "nonexistent"]
            )

    def test_all_valid_pillars_accepted(self):
        """All six valid pillar values should be accepted without error."""
        graph = _make_graph([])
        rules = []
        valid_pillars = [
            "security",
            "reliability",
            "performance_efficiency",
            "cost_optimization",
            "operational_excellence",
            "sustainability",
        ]
        # Should not raise
        findings, passed = run_static_analysis(graph, rules, focus_pillars=valid_pillars)
        assert findings == []
        assert passed == 0


# ---------------------------------------------------------------------------
# run_static_analysis - findings structure
# ---------------------------------------------------------------------------


class TestFindingsStructure:
    def test_finding_has_all_required_fields(self):
        """Each finding should have rule_id, severity, pillar, resource_logical_id, title, description, source."""
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {}),
        ])
        rule = _make_rule(
            rule_id="SEC-004",
            pillar="security",
            severity="critical",
            check="BucketEncryption",
        )
        findings, _ = run_static_analysis(graph, [rule])
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-004"
        assert f.severity == "critical"
        assert f.pillar == "security"
        assert f.resource_logical_id == "MyBucket"
        assert f.title != ""
        assert f.description != ""
        assert f.source == "static"

    def test_passed_checks_increment(self):
        """Each passing rule-resource pair should increment passed_checks by 1."""
        graph = _make_graph([
            ("Bucket1", "AWS::S3::Bucket", {"BucketEncryption": {"Config": True}}),
            ("Bucket2", "AWS::S3::Bucket", {"BucketEncryption": {"Config": True}}),
        ])
        rule = _make_rule(check="BucketEncryption")
        findings, passed = run_static_analysis(graph, [rule])
        assert findings == []
        assert passed == 2


# ---------------------------------------------------------------------------
# run_static_analysis - findings + passed_checks invariant
# ---------------------------------------------------------------------------


class TestFindingsPassedInvariant:
    def test_sum_equals_total_evaluations(self):
        """findings count + passed_checks should equal total (resource, applicable_rule) pairs."""
        graph = _make_graph([
            ("Bucket1", "AWS::S3::Bucket", {"BucketEncryption": {"Rules": [{}]}}),
            ("Bucket2", "AWS::S3::Bucket", {}),
            ("Function1", "AWS::Lambda::Function", {"TracingConfig": {"Mode": "Active"}}),
        ])
        rules = [
            _make_rule(
                rule_id="SEC-004",
                resource_types=["AWS::S3::Bucket"],
                check="BucketEncryption",
            ),
            _make_rule(
                rule_id="SEC-014",
                resource_types=["AWS::Lambda::Function"],
                check="TracingConfig",
            ),
        ]
        findings, passed = run_static_analysis(graph, rules)

        # Bucket1 matches SEC-004 → passes (1 pass)
        # Bucket2 matches SEC-004 → fails (1 finding)
        # Function1 matches SEC-014 → passes (1 pass)
        # Total evaluations = 3
        assert len(findings) + passed == 3
        assert len(findings) == 1
        assert passed == 2


# ---------------------------------------------------------------------------
# Integration with real rules file
# ---------------------------------------------------------------------------


class TestWithRealRules:
    def test_s3_bucket_without_encryption_produces_finding(self):
        """An S3 bucket without BucketEncryption should trigger SEC-004."""
        rules = load_rules()
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {"BucketName": "test-bucket"}),
        ])
        findings, passed = run_static_analysis(graph, rules)
        # Should have at least one finding for the bucket
        bucket_findings = [
            f for f in findings if f.resource_logical_id == "MyBucket"
        ]
        assert len(bucket_findings) > 0

    def test_resource_type_not_in_any_rule_excluded(self):
        """A resource type not covered by any rule should produce no findings."""
        rules = load_rules()
        # Use a resource type that truly isn't in any rule
        graph = _make_graph([
            ("MyWaitHandle", "AWS::CloudFormation::WaitConditionHandle", {}),
        ])
        findings, passed = run_static_analysis(graph, rules)
        assert findings == []
        assert passed == 0

    def test_focus_pillars_with_real_rules(self):
        """Filtering by 'sustainability' should only return sustainability findings."""
        rules = load_rules()
        graph = _make_graph([
            ("MyBucket", "AWS::S3::Bucket", {}),
            ("MyFunction", "AWS::Lambda::Function", {"Runtime": "python3.13"}),
        ])
        findings, _ = run_static_analysis(
            graph, rules, focus_pillars=["sustainability"]
        )
        for f in findings:
            assert f.pillar == "sustainability"

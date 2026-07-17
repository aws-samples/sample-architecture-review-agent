"""Unit tests for the Response Composer module."""

from src.models import (
    Finding,
    Fix,
    ResourceGraph,
    ResourceNode,
    ReviewResponse,
    SemanticFinding,
    StaticFinding,
)
from src.response_composer import compose_response


def _make_graph(*resources: tuple[str, str]) -> ResourceGraph:
    """Helper to create a ResourceGraph with given (logical_id, type) pairs."""
    nodes = [ResourceNode(logical_id=lid, resource_type=rtype, properties={}) for lid, rtype in resources]
    return ResourceGraph(nodes=nodes)


class TestComposeResponseBasic:
    """Basic response composition tests."""

    def test_empty_findings_returns_empty_response(self):
        graph = _make_graph(("MyBucket", "AWS::S3::Bucket"))
        result = compose_response(
            static_findings=[],
            semantic_findings=[],
            fixes={},
            graph=graph,
            passed_checks=5,
        )
        assert result.summary.total_resources == 1
        assert result.summary.total_findings == 0
        assert result.summary.critical == 0
        assert result.summary.warning == 0
        assert result.summary.info == 0
        assert result.summary.passed_checks == 5
        assert result.findings == []

    def test_single_static_finding(self):
        graph = _make_graph(("MyBucket", "AWS::S3::Bucket"))
        static = [
            StaticFinding(
                rule_id="SEC-001",
                severity="critical",
                pillar="security",
                resource_logical_id="MyBucket",
                title="S3 bucket not encrypted",
                description="Bucket lacks server-side encryption",
            )
        ]
        fixes = {"SEC-001": Fix(description="Add encryption", code="Encrypted: true")}
        result = compose_response(
            static_findings=static,
            semantic_findings=[],
            fixes=fixes,
            graph=graph,
            passed_checks=3,
        )
        assert result.summary.total_findings == 1
        assert result.summary.critical == 1
        assert result.findings[0].id == "F001"
        assert result.findings[0].severity == "critical"
        assert result.findings[0].resource == "MyBucket (AWS::S3::Bucket)"
        assert result.findings[0].source == "static"
        assert result.findings[0].fix.description == "Add encryption"

    def test_single_semantic_finding(self):
        graph = _make_graph(("MyQueue", "AWS::SQS::Queue"))
        semantic = [
            SemanticFinding(
                severity="warning",
                pillar="reliability",
                resource_logical_id="MyQueue",
                title="Dead letter queue missing",
                description="MyQueue feeds MyLambda without error handling",
                suggested_fix="Add a DLQ to MyQueue",
            )
        ]
        result = compose_response(
            static_findings=[],
            semantic_findings=semantic,
            fixes={},
            graph=graph,
            passed_checks=2,
        )
        assert result.summary.total_findings == 1
        assert result.summary.warning == 1
        assert result.findings[0].id == "F001"
        assert result.findings[0].source == "semantic"
        assert result.findings[0].fix.description == "Add a DLQ to MyQueue"


class TestSortOrder:
    """Tests for severity-based sort order."""

    def test_findings_sorted_by_severity(self):
        graph = _make_graph(
            ("BucketA", "AWS::S3::Bucket"),
            ("BucketB", "AWS::S3::Bucket"),
            ("BucketC", "AWS::S3::Bucket"),
        )
        static = [
            StaticFinding(
                rule_id="R1", severity="info", pillar="security",
                resource_logical_id="BucketA", title="Info issue", description="Desc",
            ),
            StaticFinding(
                rule_id="R2", severity="critical", pillar="security",
                resource_logical_id="BucketB", title="Critical issue", description="Desc",
            ),
            StaticFinding(
                rule_id="R3", severity="warning", pillar="security",
                resource_logical_id="BucketC", title="Warning issue", description="Desc",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
        )
        severities = [f.severity for f in result.findings]
        assert severities == ["critical", "warning", "info"]

    def test_findings_sorted_alphabetically_within_same_severity(self):
        graph = _make_graph(
            ("Zebra", "AWS::S3::Bucket"),
            ("Alpha", "AWS::S3::Bucket"),
            ("Mid", "AWS::S3::Bucket"),
        )
        static = [
            StaticFinding(
                rule_id="R1", severity="warning", pillar="security",
                resource_logical_id="Zebra", title="Issue", description="Desc",
            ),
            StaticFinding(
                rule_id="R2", severity="warning", pillar="security",
                resource_logical_id="Alpha", title="Issue2", description="Desc",
            ),
            StaticFinding(
                rule_id="R3", severity="warning", pillar="security",
                resource_logical_id="Mid", title="Issue3", description="Desc",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
        )
        resource_ids = [f.resource for f in result.findings]
        assert resource_ids == [
            "Alpha (AWS::S3::Bucket)",
            "Mid (AWS::S3::Bucket)",
            "Zebra (AWS::S3::Bucket)",
        ]

    def test_mixed_severity_and_alphabetical(self):
        graph = _make_graph(
            ("BucketB", "AWS::S3::Bucket"),
            ("BucketA", "AWS::S3::Bucket"),
        )
        static = [
            StaticFinding(
                rule_id="R1", severity="critical", pillar="security",
                resource_logical_id="BucketB", title="Critical B", description="Desc",
            ),
            StaticFinding(
                rule_id="R2", severity="critical", pillar="security",
                resource_logical_id="BucketA", title="Critical A", description="Desc",
            ),
            StaticFinding(
                rule_id="R3", severity="warning", pillar="security",
                resource_logical_id="BucketA", title="Warning A", description="Desc",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
        )
        assert result.findings[0].severity == "critical"
        assert "BucketA" in result.findings[0].resource
        assert result.findings[1].severity == "critical"
        assert "BucketB" in result.findings[1].resource
        assert result.findings[2].severity == "warning"


class TestSequentialIDs:
    """Tests for F001, F002, ... ID assignment."""

    def test_sequential_ids_assigned(self):
        graph = _make_graph(
            ("R1", "AWS::Lambda::Function"),
            ("R2", "AWS::Lambda::Function"),
            ("R3", "AWS::Lambda::Function"),
        )
        static = [
            StaticFinding(
                rule_id=f"RULE-{i}", severity="warning", pillar="security",
                resource_logical_id=f"R{i}", title=f"Issue {i}", description="Desc",
            )
            for i in range(1, 4)
        ]
        result = compose_response(
            static_findings=static, semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
        )
        ids = [f.id for f in result.findings]
        assert ids == ["F001", "F002", "F003"]

    def test_no_gaps_in_ids_after_dedup(self):
        graph = _make_graph(("Bucket", "AWS::S3::Bucket"))
        static = [
            StaticFinding(
                rule_id="SEC-001", severity="critical", pillar="security",
                resource_logical_id="Bucket", title="Not encrypted",
                description="Bucket is not encrypted",
            ),
        ]
        semantic = [
            SemanticFinding(
                severity="critical", pillar="security",
                resource_logical_id="Bucket", title="Not encrypted",
                description="Bucket and LambdaFn lack encryption",
                suggested_fix="Enable encryption",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=semantic, fixes={},
            graph=graph, passed_checks=0,
        )
        # Should be deduplicated to 1 finding
        assert len(result.findings) == 1
        assert result.findings[0].id == "F001"


class TestDeduplication:
    """Tests for finding deduplication logic."""

    def test_same_resource_same_pillar_same_intent_deduplicates(self):
        graph = _make_graph(("MyBucket", "AWS::S3::Bucket"))
        static = [
            StaticFinding(
                rule_id="SEC-001", severity="critical", pillar="security",
                resource_logical_id="MyBucket",
                title="S3 bucket encryption missing",
                description="No encryption configured",
            ),
        ]
        semantic = [
            SemanticFinding(
                severity="critical", pillar="security",
                resource_logical_id="MyBucket",
                title="S3 bucket encryption missing",
                description="MyBucket and MyLambda connected without encryption",
                suggested_fix="Add SSE-S3 encryption",
            ),
        ]
        fixes = {
            "SEC-001": Fix(description="Add BucketEncryption property", code="BucketEncryption: ..."),
        }
        result = compose_response(
            static_findings=static, semantic_findings=semantic, fixes=fixes,
            graph=graph, passed_checks=1,
        )
        # Only one finding after dedup
        assert len(result.findings) == 1
        # Retained semantic
        assert result.findings[0].source == "semantic"
        assert result.findings[0].description == "MyBucket and MyLambda connected without encryption"
        # Merged fixes - semantic fix description included
        assert "Add SSE-S3 encryption" in result.findings[0].fix.description

    def test_different_pillars_not_deduplicated(self):
        graph = _make_graph(("MyBucket", "AWS::S3::Bucket"))
        static = [
            StaticFinding(
                rule_id="SEC-001", severity="critical", pillar="security",
                resource_logical_id="MyBucket",
                title="Encryption missing",
                description="No encryption",
            ),
        ]
        semantic = [
            SemanticFinding(
                severity="warning", pillar="reliability",
                resource_logical_id="MyBucket",
                title="Encryption missing",
                description="MyBucket and MyBackup need encryption for durability",
                suggested_fix="Add encryption",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=semantic, fixes={},
            graph=graph, passed_checks=0,
        )
        # Not deduplicated because different pillars
        assert len(result.findings) == 2

    def test_different_resources_not_deduplicated(self):
        graph = _make_graph(
            ("BucketA", "AWS::S3::Bucket"),
            ("BucketB", "AWS::S3::Bucket"),
        )
        static = [
            StaticFinding(
                rule_id="SEC-001", severity="critical", pillar="security",
                resource_logical_id="BucketA",
                title="Encryption missing",
                description="No encryption",
            ),
        ]
        semantic = [
            SemanticFinding(
                severity="critical", pillar="security",
                resource_logical_id="BucketB",
                title="Encryption missing",
                description="BucketB needs encryption",
                suggested_fix="Enable encryption",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=semantic, fixes={},
            graph=graph, passed_checks=0,
        )
        assert len(result.findings) == 2

    def test_merge_fixes_combines_descriptions(self):
        graph = _make_graph(("MyFunc", "AWS::Lambda::Function"))
        static = [
            StaticFinding(
                rule_id="SEC-010", severity="warning", pillar="security",
                resource_logical_id="MyFunc",
                title="Lambda missing VPC config",
                description="Function not in VPC",
            ),
        ]
        semantic = [
            SemanticFinding(
                severity="warning", pillar="security",
                resource_logical_id="MyFunc",
                title="Lambda missing VPC config",
                description="MyFunc and MyDB should be in same VPC",
                suggested_fix="Add VpcConfig with SubnetIds and SecurityGroupIds",
            ),
        ]
        fixes = {
            "SEC-010": Fix(description="Add VpcConfig property", code="VpcConfig:\n  SubnetIds: []"),
        }
        result = compose_response(
            static_findings=static, semantic_findings=semantic, fixes=fixes,
            graph=graph, passed_checks=0,
        )
        assert len(result.findings) == 1
        # Both fix descriptions should be present
        assert "VpcConfig" in result.findings[0].fix.description


class TestSummaryComputation:
    """Tests for summary statistics."""

    def test_summary_counts_match_findings(self):
        graph = _make_graph(
            ("R1", "AWS::Lambda::Function"),
            ("R2", "AWS::S3::Bucket"),
            ("R3", "AWS::DynamoDB::Table"),
        )
        static = [
            StaticFinding(
                rule_id="R1", severity="critical", pillar="security",
                resource_logical_id="R1", title="Issue", description="Desc",
            ),
            StaticFinding(
                rule_id="R2", severity="warning", pillar="reliability",
                resource_logical_id="R2", title="Issue", description="Desc",
            ),
            StaticFinding(
                rule_id="R3", severity="info", pillar="cost_optimization",
                resource_logical_id="R3", title="Issue", description="Desc",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=[], fixes={},
            graph=graph, passed_checks=10,
        )
        assert result.summary.total_resources == 3
        assert result.summary.total_findings == 3
        assert result.summary.critical == 1
        assert result.summary.warning == 1
        assert result.summary.info == 1
        assert result.summary.passed_checks == 10
        assert result.summary.total_findings == result.summary.critical + result.summary.warning + result.summary.info

    def test_total_resources_from_graph(self):
        graph = _make_graph(
            ("A", "AWS::Lambda::Function"),
            ("B", "AWS::Lambda::Function"),
            ("C", "AWS::Lambda::Function"),
            ("D", "AWS::Lambda::Function"),
            ("E", "AWS::Lambda::Function"),
        )
        result = compose_response(
            static_findings=[], semantic_findings=[], fixes={},
            graph=graph, passed_checks=20,
        )
        assert result.summary.total_resources == 5
        assert result.summary.total_findings == 0


class TestSemanticUnavailable:
    """Tests for semantic_unavailable flag handling."""

    def test_semantic_unavailable_adds_warning_finding(self):
        graph = _make_graph(("MyBucket", "AWS::S3::Bucket"))
        result = compose_response(
            static_findings=[], semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
            semantic_unavailable=True,
        )
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == "info"
        assert f.pillar == "operational_excellence"
        assert f.title == "Semantic analysis unavailable"
        assert f.source == "semantic"
        assert "static analysis only" in f.description

    def test_semantic_unavailable_included_in_summary_count(self):
        graph = _make_graph(("MyBucket", "AWS::S3::Bucket"))
        result = compose_response(
            static_findings=[], semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
            semantic_unavailable=True,
        )
        assert result.summary.total_findings == 1
        assert result.summary.info == 1


class TestMemoryUnavailable:
    """Tests for memory_unavailable flag handling."""

    def test_memory_unavailable_adds_info_finding(self):
        graph = _make_graph(("MyBucket", "AWS::S3::Bucket"))
        result = compose_response(
            static_findings=[], semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
            memory_unavailable=True,
        )
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == "info"
        assert f.pillar == "operational_excellence"
        assert f.title == "Organization rules could not be loaded"
        assert f.source == "org_rule"
        assert "built-in rules only" in f.description

    def test_both_flags_add_two_findings(self):
        graph = _make_graph(("MyBucket", "AWS::S3::Bucket"))
        result = compose_response(
            static_findings=[], semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
            semantic_unavailable=True,
            memory_unavailable=True,
        )
        assert len(result.findings) == 2
        assert result.summary.total_findings == 2
        assert result.summary.info == 2
        titles = {f.title for f in result.findings}
        assert "Semantic analysis unavailable" in titles
        assert "Organization rules could not be loaded" in titles


class TestResourceDisplay:
    """Tests for resource field composition."""

    def test_resource_field_shows_logical_id_and_type(self):
        graph = _make_graph(("MyFunction", "AWS::Lambda::Function"))
        static = [
            StaticFinding(
                rule_id="R1", severity="warning", pillar="security",
                resource_logical_id="MyFunction", title="Issue", description="Desc",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
        )
        assert result.findings[0].resource == "MyFunction (AWS::Lambda::Function)"

    def test_resource_not_in_graph_shows_only_logical_id(self):
        graph = _make_graph(("OtherResource", "AWS::S3::Bucket"))
        static = [
            StaticFinding(
                rule_id="R1", severity="warning", pillar="security",
                resource_logical_id="MissingResource", title="Issue", description="Desc",
            ),
        ]
        result = compose_response(
            static_findings=static, semantic_findings=[], fixes={},
            graph=graph, passed_checks=0,
        )
        assert result.findings[0].resource == "MissingResource"


class TestCompleteScenario:
    """Integration-style tests for full response composition."""

    def test_full_scenario_with_dedup_sort_and_flags(self):
        graph = _make_graph(
            ("MyBucket", "AWS::S3::Bucket"),
            ("MyLambda", "AWS::Lambda::Function"),
            ("MyTable", "AWS::DynamoDB::Table"),
        )
        static = [
            StaticFinding(
                rule_id="SEC-001", severity="critical", pillar="security",
                resource_logical_id="MyBucket",
                title="Bucket not encrypted",
                description="No encryption on bucket",
            ),
            StaticFinding(
                rule_id="REL-001", severity="warning", pillar="reliability",
                resource_logical_id="MyLambda",
                title="No DLQ configured",
                description="Lambda lacks dead letter queue",
            ),
        ]
        semantic = [
            SemanticFinding(
                severity="critical", pillar="security",
                resource_logical_id="MyBucket",
                title="Bucket not encrypted",
                description="MyBucket feeds MyLambda without encryption",
                suggested_fix="Enable SSE-S3",
            ),
            SemanticFinding(
                severity="info", pillar="cost_optimization",
                resource_logical_id="MyTable",
                title="Over-provisioned capacity",
                description="MyTable and MyLambda could use on-demand",
                suggested_fix="Switch to PAY_PER_REQUEST",
            ),
        ]
        fixes = {
            "SEC-001": Fix(description="Add BucketEncryption", code="BucketEncryption: ..."),
            "REL-001": Fix(description="Add DLQ config", code="DeadLetterConfig: ..."),
        }
        result = compose_response(
            static_findings=static,
            semantic_findings=semantic,
            fixes=fixes,
            graph=graph,
            passed_checks=5,
            semantic_unavailable=False,
            memory_unavailable=False,
        )
        # After dedup: MyBucket(semantic), MyLambda(static), MyTable(semantic) = 3
        assert result.summary.total_findings == 3
        assert result.summary.total_resources == 3
        assert result.summary.critical == 1
        assert result.summary.warning == 1
        assert result.summary.info == 1
        assert result.summary.passed_checks == 5

        # Sort: critical first (MyBucket), then warning (MyLambda), then info (MyTable)
        assert result.findings[0].severity == "critical"
        assert "MyBucket" in result.findings[0].resource
        assert result.findings[0].source == "semantic"  # Deduped: retained semantic

        assert result.findings[1].severity == "warning"
        assert "MyLambda" in result.findings[1].resource

        assert result.findings[2].severity == "info"
        assert "MyTable" in result.findings[2].resource

        # Sequential IDs
        assert [f.id for f in result.findings] == ["F001", "F002", "F003"]

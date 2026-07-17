"""Unit tests for the semantic analysis engine.

Tests cover prompt construction, response parsing, error handling,
and org rule integration. All tests mock the boto3 client to avoid
actual API calls.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.models import (
    ArchPattern,
    OrgRule,
    ResourceEdge,
    ResourceGraph,
    ResourceNode,
    SemanticFinding,
)
from src.semantic_analyzer import (
    _build_prompt_payload,
    _parse_findings,
    run_semantic_analysis,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def simple_graph() -> ResourceGraph:
    """A simple ResourceGraph with two resources and one edge."""
    return ResourceGraph(
        nodes=[
            ResourceNode(
                logical_id="MyQueue",
                resource_type="AWS::SQS::Queue",
                properties={"VisibilityTimeout": 30},
            ),
            ResourceNode(
                logical_id="MyFunction",
                resource_type="AWS::Lambda::Function",
                properties={
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                },
            ),
        ],
        edges=[
            ResourceEdge(
                source="MyFunction",
                target="MyQueue",
                reference_type="Ref",
            ),
        ],
        patterns=[
            ArchPattern(
                pattern_type="async_pipeline",
                resources=["MyQueue", "MyFunction"],
                description="SQS queue feeding Lambda function",
            ),
        ],
        template_format="yaml",
    )


@pytest.fixture
def sample_org_rules() -> list[OrgRule]:
    """Sample organization rules."""
    return [
        OrgRule(
            rule_id="org-001",
            rule_text="All Lambda functions must have a DLQ configured",
            severity="critical",
            pillar="reliability",
        ),
        OrgRule(
            rule_id="org-002",
            rule_text="SQS queues must use encryption at rest",
            severity="warning",
            pillar="security",
        ),
    ]


def _make_bedrock_response(findings_json: list[dict]) -> MagicMock:
    """Create a mock Bedrock response with the given findings JSON."""
    response_body = {
        "content": [
            {
                "type": "text",
                "text": json.dumps(findings_json),
            }
        ],
    }
    mock_body = MagicMock()
    mock_body.read.return_value = json.dumps(response_body).encode("utf-8")
    return {"body": mock_body}


# ---------------------------------------------------------------------------
# Tests: _build_prompt_payload
# ---------------------------------------------------------------------------


class TestBuildPromptPayload:
    """Tests for prompt payload construction."""

    def test_serializes_resources(self, simple_graph: ResourceGraph) -> None:
        """Resources are serialized with logical_id, type, and properties."""
        payload = _build_prompt_payload(simple_graph)

        assert len(payload["resources"]) == 2
        assert payload["resources"][0]["logical_id"] == "MyQueue"
        assert payload["resources"][0]["resource_type"] == "AWS::SQS::Queue"
        assert payload["resources"][0]["properties"] == {"VisibilityTimeout": 30}

    def test_serializes_edges(self, simple_graph: ResourceGraph) -> None:
        """Edges are serialized with source, target, and reference_type."""
        payload = _build_prompt_payload(simple_graph)

        assert len(payload["edges"]) == 1
        assert payload["edges"][0]["source"] == "MyFunction"
        assert payload["edges"][0]["target"] == "MyQueue"
        assert payload["edges"][0]["reference_type"] == "Ref"

    def test_serializes_patterns(self, simple_graph: ResourceGraph) -> None:
        """Architectural patterns are included in the payload."""
        payload = _build_prompt_payload(simple_graph)

        assert len(payload["patterns"]) == 1
        assert payload["patterns"][0]["pattern_type"] == "async_pipeline"
        assert "MyQueue" in payload["patterns"][0]["resources"]

    def test_includes_context(self, simple_graph: ResourceGraph) -> None:
        """Workload context is included when provided."""
        payload = _build_prompt_payload(
            simple_graph, context="Payment processing pipeline"
        )

        assert payload["context"] == "Payment processing pipeline"

    def test_context_defaults_to_empty_string(
        self, simple_graph: ResourceGraph
    ) -> None:
        """Context defaults to empty string when not provided."""
        payload = _build_prompt_payload(simple_graph)
        assert payload["context"] == ""

    def test_includes_org_rules(
        self, simple_graph: ResourceGraph, sample_org_rules: list[OrgRule]
    ) -> None:
        """Org rules are serialized into the payload."""
        payload = _build_prompt_payload(
            simple_graph, org_rules=sample_org_rules
        )

        assert len(payload["org_rules"]) == 2
        assert payload["org_rules"][0]["rule_id"] == "org-001"
        assert payload["org_rules"][0]["rule_text"] == (
            "All Lambda functions must have a DLQ configured"
        )
        assert payload["org_rules"][0]["severity"] == "critical"
        assert payload["org_rules"][0]["pillar"] == "reliability"

    def test_org_rules_empty_when_none(
        self, simple_graph: ResourceGraph
    ) -> None:
        """Org rules list is empty when None is passed."""
        payload = _build_prompt_payload(simple_graph, org_rules=None)
        assert payload["org_rules"] == []

    def test_payload_is_json_serializable(
        self, simple_graph: ResourceGraph, sample_org_rules: list[OrgRule]
    ) -> None:
        """The entire payload is JSON-serializable."""
        payload = _build_prompt_payload(
            simple_graph,
            context="test context",
            org_rules=sample_org_rules,
        )
        # Should not raise
        serialized = json.dumps(payload)
        assert isinstance(serialized, str)


# ---------------------------------------------------------------------------
# Tests: _parse_findings
# ---------------------------------------------------------------------------


class TestParseFindings:
    """Tests for parsing FM response text into SemanticFinding objects."""

    def test_parses_valid_findings(self) -> None:
        """Valid JSON array is parsed into SemanticFinding objects."""
        response = json.dumps([
            {
                "severity": "critical",
                "pillar": "reliability",
                "resource_logical_id": "MyFunction",
                "title": "No DLQ configured",
                "description": (
                    "MyFunction processes messages from MyQueue but has no "
                    "dead-letter queue for failed invocations"
                ),
                "suggested_fix": "Add a DeadLetterConfig to MyFunction",
                "source": "semantic",
            }
        ])

        findings = _parse_findings(response)

        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].pillar == "reliability"
        assert findings[0].resource_logical_id == "MyFunction"
        assert findings[0].title == "No DLQ configured"
        assert "MyFunction" in findings[0].description
        assert "MyQueue" in findings[0].description
        assert findings[0].source == "semantic"

    def test_parses_org_rule_findings(self) -> None:
        """Findings with source='org_rule' are correctly parsed."""
        response = json.dumps([
            {
                "severity": "warning",
                "pillar": "security",
                "resource_logical_id": "MyQueue",
                "title": "Queue encryption missing",
                "description": (
                    "MyQueue connected to MyFunction does not have "
                    "encryption at rest enabled"
                ),
                "suggested_fix": "Add KmsMasterKeyId property",
                "source": "org_rule",
            }
        ])

        findings = _parse_findings(response)

        assert len(findings) == 1
        assert findings[0].source == "org_rule"

    def test_handles_markdown_code_fences(self) -> None:
        """Response wrapped in markdown code fences is still parsed."""
        findings_data = [
            {
                "severity": "info",
                "pillar": "cost_optimization",
                "resource_logical_id": "MyFunction",
                "title": "Over-provisioned memory",
                "description": (
                    "MyFunction serving MyQueue has default memory which "
                    "may be over-provisioned"
                ),
                "suggested_fix": "Consider reducing MemorySize",
                "source": "semantic",
            }
        ]
        response = f"```json\n{json.dumps(findings_data)}\n```"

        findings = _parse_findings(response)

        assert len(findings) == 1
        assert findings[0].title == "Over-provisioned memory"

    def test_returns_empty_for_invalid_json(self) -> None:
        """Invalid JSON returns an empty list."""
        findings = _parse_findings("this is not json")
        assert findings == []

    def test_returns_empty_for_non_array(self) -> None:
        """Non-array JSON returns an empty list."""
        findings = _parse_findings('{"not": "an array"}')
        assert findings == []

    def test_skips_findings_missing_required_fields(self) -> None:
        """Findings without required fields are skipped."""
        response = json.dumps([
            {
                "severity": "critical",
                "pillar": "security",
                # Missing resource_logical_id, title, description
            },
            {
                "severity": "warning",
                "pillar": "reliability",
                "resource_logical_id": "MyFunc",
                "title": "Valid finding",
                "description": "MyFunc and MyQueue have an issue",
                "source": "semantic",
            },
        ])

        findings = _parse_findings(response)

        assert len(findings) == 1
        assert findings[0].title == "Valid finding"

    def test_defaults_invalid_severity_to_info(self) -> None:
        """Unknown severity values default to 'info'."""
        response = json.dumps([
            {
                "severity": "unknown_value",
                "pillar": "security",
                "resource_logical_id": "MyResource",
                "title": "Test",
                "description": "MyResource and OtherResource issue",
                "source": "semantic",
            }
        ])

        findings = _parse_findings(response)

        assert len(findings) == 1
        assert findings[0].severity == "info"

    def test_defaults_invalid_source_to_semantic(self) -> None:
        """Unknown source values default to 'semantic'."""
        response = json.dumps([
            {
                "severity": "warning",
                "pillar": "security",
                "resource_logical_id": "MyResource",
                "title": "Test",
                "description": "MyResource and OtherResource issue",
                "source": "unknown_source",
            }
        ])

        findings = _parse_findings(response)

        assert len(findings) == 1
        assert findings[0].source == "semantic"


# ---------------------------------------------------------------------------
# Tests: run_semantic_analysis
# ---------------------------------------------------------------------------


class TestRunSemanticAnalysis:
    """Tests for the main run_semantic_analysis function."""

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_successful_invocation(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """Successful FM invocation returns findings and False flag."""
        findings_data = [
            {
                "severity": "critical",
                "pillar": "reliability",
                "resource_logical_id": "MyFunction",
                "title": "No error recovery",
                "description": (
                    "MyFunction processes from MyQueue without a DLQ"
                ),
                "suggested_fix": "Add DeadLetterConfig",
                "source": "semantic",
            }
        ]
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response(
            findings_data
        )
        mock_create_client.return_value = mock_client

        findings, unavailable = run_semantic_analysis(simple_graph)

        assert unavailable is False
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].source == "semantic"

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_passes_context_to_prompt(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """Workload context is included in the FM invocation."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response([])
        mock_create_client.return_value = mock_client

        run_semantic_analysis(
            simple_graph, context="Payment processing pipeline"
        )

        # Verify the invoke_model call included the context
        call_args = mock_client.invoke_model.call_args
        request_body = json.loads(call_args[1]["body"])
        user_message = request_body["messages"][0]["content"]
        assert "Payment processing pipeline" in user_message

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_passes_org_rules_to_prompt(
        self,
        mock_create_client: MagicMock,
        simple_graph: ResourceGraph,
        sample_org_rules: list[OrgRule],
    ) -> None:
        """Org rules are included in the FM invocation."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response([])
        mock_create_client.return_value = mock_client

        run_semantic_analysis(simple_graph, org_rules=sample_org_rules)

        # Verify org rules are in the request
        call_args = mock_client.invoke_model.call_args
        request_body = json.loads(call_args[1]["body"])
        user_message = request_body["messages"][0]["content"]
        assert "org-001" in user_message
        assert "All Lambda functions must have a DLQ configured" in user_message

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_uses_correct_model_id(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """The correct model ID is used for invocation."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response([])
        mock_create_client.return_value = mock_client

        run_semantic_analysis(simple_graph)

        call_args = mock_client.invoke_model.call_args
        assert call_args[1]["modelId"] == "us.anthropic.claude-sonnet-4-6"

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_handles_client_error_gracefully(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """ClientError returns empty list and True flag."""
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "InvokeModel",
        )
        mock_create_client.return_value = mock_client

        findings, unavailable = run_semantic_analysis(simple_graph)

        assert findings == []
        assert unavailable is True

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_handles_timeout_error_gracefully(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """Timeout exceptions return empty list and True flag."""
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = TimeoutError(
            "Read timeout on endpoint"
        )
        mock_create_client.return_value = mock_client

        findings, unavailable = run_semantic_analysis(simple_graph)

        assert findings == []
        assert unavailable is True

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_handles_unexpected_exception_gracefully(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """Unexpected exceptions return empty list and True flag."""
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = RuntimeError(
            "Unexpected service error"
        )
        mock_create_client.return_value = mock_client

        findings, unavailable = run_semantic_analysis(simple_graph)

        assert findings == []
        assert unavailable is True

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_handles_empty_fm_response(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """Empty FM response returns empty list and True flag."""
        response_body = {"content": []}
        mock_body = MagicMock()
        mock_body.read.return_value = json.dumps(response_body).encode("utf-8")
        mock_response = {"body": mock_body}

        mock_client = MagicMock()
        mock_client.invoke_model.return_value = mock_response
        mock_create_client.return_value = mock_client

        findings, unavailable = run_semantic_analysis(simple_graph)

        assert findings == []
        assert unavailable is True

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_org_rule_violations_have_correct_source(
        self,
        mock_create_client: MagicMock,
        simple_graph: ResourceGraph,
        sample_org_rules: list[OrgRule],
    ) -> None:
        """Org rule violation findings have source='org_rule'."""
        findings_data = [
            {
                "severity": "critical",
                "pillar": "reliability",
                "resource_logical_id": "MyFunction",
                "title": "DLQ not configured (org rule violation)",
                "description": (
                    "MyFunction connected to MyQueue violates org rule: "
                    "All Lambda functions must have a DLQ configured"
                ),
                "suggested_fix": "Add DeadLetterConfig to MyFunction",
                "source": "org_rule",
            }
        ]
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response(
            findings_data
        )
        mock_create_client.return_value = mock_client

        findings, unavailable = run_semantic_analysis(
            simple_graph, org_rules=sample_org_rules
        )

        assert unavailable is False
        assert len(findings) == 1
        assert findings[0].source == "org_rule"

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_prompt_uses_structured_json_not_raw_text(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """Prompt sends template as structured JSON data, not raw text."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response([])
        mock_create_client.return_value = mock_client

        run_semantic_analysis(simple_graph)

        call_args = mock_client.invoke_model.call_args
        request_body = json.loads(call_args[1]["body"])
        user_message = request_body["messages"][0]["content"]

        # The message should contain the structured JSON payload
        assert '"resources"' in user_message
        assert '"edges"' in user_message
        assert '"patterns"' in user_message
        # Verify it's parseable JSON within the message
        assert '"logical_id"' in user_message
        assert '"resource_type"' in user_message

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_system_prompt_included(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """System prompt is included in the request body."""
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response([])
        mock_create_client.return_value = mock_client

        run_semantic_analysis(simple_graph)

        call_args = mock_client.invoke_model.call_args
        request_body = json.loads(call_args[1]["body"])
        assert "system" in request_body
        assert "Well-Architected" in request_body["system"]

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_finding_description_references_resource_ids(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """Finding descriptions reference at least two resource logical IDs."""
        findings_data = [
            {
                "severity": "warning",
                "pillar": "reliability",
                "resource_logical_id": "MyFunction",
                "title": "Missing error handling",
                "description": (
                    "The async pipeline between MyQueue and MyFunction lacks "
                    "error recovery. Failed messages from MyQueue will be lost "
                    "when MyFunction invocation fails."
                ),
                "suggested_fix": "Add a DLQ to MyQueue or MyFunction",
                "source": "semantic",
            }
        ]
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_bedrock_response(
            findings_data
        )
        mock_create_client.return_value = mock_client

        findings, unavailable = run_semantic_analysis(simple_graph)

        assert unavailable is False
        assert len(findings) == 1
        # Verify at least two resource IDs in description
        desc = findings[0].description
        assert "MyQueue" in desc
        assert "MyFunction" in desc

    @patch("src.semantic_analyzer._create_bedrock_client")
    def test_handles_service_error(
        self, mock_create_client: MagicMock, simple_graph: ResourceGraph
    ) -> None:
        """Bedrock service errors (5xx) return empty list and True flag."""
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ServiceUnavailableException",
                    "Message": "Service is temporarily unavailable",
                }
            },
            "InvokeModel",
        )
        mock_create_client.return_value = mock_client

        findings, unavailable = run_semantic_analysis(simple_graph)

        assert findings == []
        assert unavailable is True

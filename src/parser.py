"""CloudFormation template parser.

Handles YAML/JSON auto-detection, parsing, Resource Graph construction,
and inter-resource reference extraction (Ref, Fn::GetAtt, Fn::Sub, DependsOn).
"""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from src.models import (
    ArchPattern,
    EmptyTemplateError,
    InvalidFormatError,
    ParseError,
    ResourceEdge,
    ResourceGraph,
    ResourceLimitError,
    ResourceNode,
)

_MAX_RESOURCES = 200

# Maximum template size in bytes (1 MB) to prevent resource exhaustion during parsing
_MAX_TEMPLATE_SIZE = 1 * 1024 * 1024  # 1 MB

# Maximum number of YAML aliases (anchor references) to prevent Billion Laughs attacks
_MAX_YAML_ALIASES = 1000

# Pattern for ${LogicalId} or ${LogicalId.Attribute} references in Fn::Sub strings
_SUB_REF_PATTERN = re.compile(r"\$\{([A-Za-z][A-Za-z0-9]*?)(?:\.[A-Za-z]+)?\}")


def parse_template(template: str, declared_format: str) -> ResourceGraph:
    """Parse a CloudFormation template into a ResourceGraph.

    Args:
        template: Raw template content (YAML or JSON string).
        declared_format: Must be exactly "cloudformation" (case-sensitive).

    Returns:
        ResourceGraph with nodes, edges, and template_format.
        patterns is always empty (pattern detection is a separate task).

    Raises:
        InvalidFormatError: If declared_format is not "cloudformation".
        ParseError: If the template cannot be parsed as valid YAML/JSON.
        EmptyTemplateError: If the template has no Resources section or it is empty.
        ResourceLimitError: If the template has more than 200 resources.
    """
    # Validate format parameter
    if declared_format != "cloudformation":
        raise InvalidFormatError(declared_format)

    # Enforce template size limit to prevent resource exhaustion during parsing
    if len(template.encode("utf-8")) > _MAX_TEMPLATE_SIZE:
        raise ParseError(
            line_number=1,
            description=f"Template exceeds maximum size of {_MAX_TEMPLATE_SIZE // (1024 * 1024)} MB",
        )

    # Auto-detect format and parse
    stripped = template.lstrip()
    if stripped.startswith("{"):
        detected_format = "json"
        parsed = _parse_json(template)
    else:
        detected_format = "yaml"
        parsed = _parse_yaml(template)

    # Validate parsed content is a dict
    if not isinstance(parsed, dict):
        raise ParseError(
            line_number=1,
            description="Template must be a mapping/object at the top level",
        )

    # Extract Resources section
    resources = parsed.get("Resources")
    if not resources or not isinstance(resources, dict) or len(resources) == 0:
        raise EmptyTemplateError()

    # Enforce resource limit
    if len(resources) > _MAX_RESOURCES:
        raise ResourceLimitError()

    # Build resource nodes
    nodes = _build_nodes(resources)

    # Build set of valid logical IDs for edge filtering
    logical_ids = {node.logical_id for node in nodes}

    # Build edges from references
    edges = _build_edges(resources, logical_ids)

    graph = ResourceGraph(
        nodes=nodes,
        edges=edges,
        patterns=[],
        template_format=detected_format,
    )

    # Detect architectural patterns from resource relationships
    graph.patterns = detect_patterns(graph)

    return graph


def _parse_json(template: str) -> Any:
    """Parse template as JSON, raising ParseError on failure."""
    try:
        return json.loads(template)
    except json.JSONDecodeError as e:
        raise ParseError(
            line_number=e.lineno or 1,
            description=e.msg,
        ) from e


# CloudFormation shorthand intrinsic tags (e.g. `!GetAtt`, `!Ref`, `!Sub`).
# Standard YAML safe_load cannot construct these, so we register constructors
# that normalize them to the longhand `{"Fn::X": ...}` / `{"Ref": ...}` form the
# rest of the parser already understands.
_CFN_TAGS = (
    "Ref", "Condition",
    "Fn::GetAtt", "Fn::Sub", "Fn::Join", "Fn::Select", "Fn::Split",
    "Fn::FindInMap", "Fn::Base64", "Fn::Cidr", "Fn::GetAZs",
    "Fn::ImportValue", "Fn::If", "Fn::Equals", "Fn::And", "Fn::Or",
    "Fn::Not", "Fn::Transform", "Fn::Length", "Fn::ToJsonString",
)


class _CfnYamlLoader(yaml.SafeLoader):
    """SafeLoader that understands CloudFormation `!Xxx` shorthand tags.

    Includes protection against YAML Billion Laughs (entity expansion) attacks
    by limiting the number of alias resolutions during parsing.
    """

    _alias_count = 0

    def get_node(self):
        """Reset alias counter at the start of each document parse."""
        self._alias_count = 0
        return super().get_node()

    def compose_node(self, parent, index):
        """Override to count alias resolutions and enforce the limit."""
        if self.check_event(yaml.AliasEvent):
            self._alias_count += 1
            if self._alias_count > _MAX_YAML_ALIASES:
                raise yaml.YAMLError(
                    f"YAML document exceeds maximum alias limit ({_MAX_YAML_ALIASES}). "
                    "This may indicate a Billion Laughs (entity expansion) attack."
                )
        return super().compose_node(parent, index)


def _make_cfn_constructor(full_name: str):
    def constructor(loader: yaml.Loader, node: yaml.Node) -> dict:
        if isinstance(node, yaml.ScalarNode):
            value: Any = loader.construct_scalar(node)
            # !GetAtt accepts a dotted string ("Res.Attr") → longhand list form.
            if full_name == "Fn::GetAtt" and isinstance(value, str):
                value = value.split(".", 1)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        else:  # MappingNode
            value = loader.construct_mapping(node, deep=True)
        return {full_name: value}
    return constructor


for _tag in _CFN_TAGS:
    _short = _tag.split("::")[-1]  # "Fn::GetAtt" -> "GetAtt", "Ref" -> "Ref"
    _CfnYamlLoader.add_constructor(f"!{_short}", _make_cfn_constructor(_tag))


def _parse_yaml(template: str) -> Any:
    """Parse template as YAML (incl. CloudFormation shorthand), raising ParseError."""
    try:
        return yaml.load(template, Loader=_CfnYamlLoader)
    except yaml.YAMLError as e:
        line_number = 1
        description = str(e)
        if hasattr(e, "problem_mark") and e.problem_mark is not None:
            line_number = e.problem_mark.line + 1  # YAML lines are 0-indexed
            description = getattr(e, "problem", str(e))
        raise ParseError(
            line_number=line_number,
            description=description,
        ) from e


def _build_nodes(resources: dict[str, Any]) -> list[ResourceNode]:
    """Build ResourceNode objects from the Resources section."""
    nodes = []
    for logical_id, resource_def in resources.items():
        if not isinstance(resource_def, dict):
            continue
        resource_type = resource_def.get("Type", "")
        properties = resource_def.get("Properties", {})
        if not isinstance(properties, dict):
            properties = {}
        nodes.append(
            ResourceNode(
                logical_id=logical_id,
                resource_type=resource_type,
                properties=properties,
            )
        )
    return nodes


def _build_edges(
    resources: dict[str, Any], logical_ids: set[str]
) -> list[ResourceEdge]:
    """Build ResourceEdge objects by scanning for Ref, Fn::GetAtt, Fn::Sub, DependsOn."""
    edges: list[ResourceEdge] = []
    seen: set[tuple[str, str, str, str | None]] = set()

    for logical_id, resource_def in resources.items():
        if not isinstance(resource_def, dict):
            continue

        # Scan DependsOn (top-level resource property, not inside Properties)
        depends_on = resource_def.get("DependsOn")
        if depends_on is not None:
            deps = [depends_on] if isinstance(depends_on, str) else depends_on
            if isinstance(deps, list):
                for dep in deps:
                    if isinstance(dep, str) and dep in logical_ids and dep != logical_id:
                        key = (logical_id, dep, "DependsOn", None)
                        if key not in seen:
                            seen.add(key)
                            edges.append(
                                ResourceEdge(
                                    source=logical_id,
                                    target=dep,
                                    reference_type="DependsOn",
                                )
                            )

        # Scan the rest of the resource definition for Ref, Fn::GetAtt, Fn::Sub
        _scan_value(resource_def, logical_id, logical_ids, edges, seen)

    return edges


def _scan_value(
    value: Any,
    source_id: str,
    logical_ids: set[str],
    edges: list[ResourceEdge],
    seen: set[tuple[str, str, str, str | None]],
) -> None:
    """Recursively scan a value for inter-resource references."""
    if isinstance(value, dict):
        # Check for Ref
        if "Ref" in value:
            ref_target = value["Ref"]
            if (
                isinstance(ref_target, str)
                and ref_target in logical_ids
                and ref_target != source_id
            ):
                key = (source_id, ref_target, "Ref", None)
                if key not in seen:
                    seen.add(key)
                    edges.append(
                        ResourceEdge(
                            source=source_id,
                            target=ref_target,
                            reference_type="Ref",
                        )
                    )

        # Check for Fn::GetAtt
        if "Fn::GetAtt" in value:
            get_att = value["Fn::GetAtt"]
            target = None
            attribute = None
            if isinstance(get_att, list) and len(get_att) >= 2:
                target = get_att[0]
                attribute = get_att[1]
            elif isinstance(get_att, str) and "." in get_att:
                parts = get_att.split(".", 1)
                target = parts[0]
                attribute = parts[1]

            if (
                target
                and isinstance(target, str)
                and target in logical_ids
                and target != source_id
            ):
                key = (source_id, target, "Fn::GetAtt", attribute)
                if key not in seen:
                    seen.add(key)
                    edges.append(
                        ResourceEdge(
                            source=source_id,
                            target=target,
                            reference_type="Fn::GetAtt",
                            attribute=attribute,
                        )
                    )

        # Check for Fn::Sub
        if "Fn::Sub" in value:
            sub_value = value["Fn::Sub"]
            sub_string = None
            if isinstance(sub_value, str):
                sub_string = sub_value
            elif isinstance(sub_value, list) and len(sub_value) >= 1:
                sub_string = sub_value[0] if isinstance(sub_value[0], str) else None

            if sub_string:
                matches = _SUB_REF_PATTERN.findall(sub_string)
                for match in matches:
                    if match in logical_ids and match != source_id:
                        # Check it's not a variable override in the second arg
                        overrides: set[str] = set()
                        if isinstance(sub_value, list) and len(sub_value) >= 2:
                            override_map = sub_value[1]
                            if isinstance(override_map, dict):
                                overrides = set(override_map.keys())
                        if match not in overrides:
                            key = (source_id, match, "Fn::Sub", None)
                            if key not in seen:
                                seen.add(key)
                                edges.append(
                                    ResourceEdge(
                                        source=source_id,
                                        target=match,
                                        reference_type="Fn::Sub",
                                    )
                                )

        # Recurse into all dict values
        for v in value.values():
            _scan_value(v, source_id, logical_ids, edges, seen)

    elif isinstance(value, list):
        for item in value:
            _scan_value(item, source_id, logical_ids, edges, seen)


# ---------------------------------------------------------------------------
# Pattern Detection
# ---------------------------------------------------------------------------

# Resource type constants for pattern detection
_SQS_QUEUE = "AWS::SQS::Queue"
_SNS_TOPIC = "AWS::SNS::Topic"
_LAMBDA_FUNCTION = "AWS::Lambda::Function"
_EVENTBRIDGE_RULE = "AWS::Events::Rule"
_S3_BUCKET = "AWS::S3::Bucket"
_APIGW_REST_API = "AWS::ApiGateway::RestApi"
_APIGW_V2_API = "AWS::ApiGatewayV2::Api"
_DYNAMODB_TABLE = "AWS::DynamoDB::Table"


def detect_patterns(graph: ResourceGraph) -> list[ArchPattern]:
    """Detect architectural patterns from resource relationships in the graph.

    Analyzes nodes and edges to identify:
    - Async pipelines: SQS → Lambda, SNS → SQS → Lambda
    - Event-driven flows: EventBridge → Lambda, S3 → Lambda
    - Request-response chains: API Gateway → Lambda → DynamoDB

    Args:
        graph: A ResourceGraph with nodes and edges already populated.

    Returns:
        List of detected ArchPattern instances.
    """
    patterns: list[ArchPattern] = []

    # Build lookup maps
    type_by_id: dict[str, str] = {
        node.logical_id: node.resource_type for node in graph.nodes
    }

    # Build adjacency sets (edges go both directions for pattern matching):
    # "connected_to[A]" = set of logical IDs that A has an edge with (in either direction)
    # We check both directions because an edge from A→B means A references B,
    # but the architectural relationship could be in either direction.
    outgoing: dict[str, set[str]] = {}  # source -> {targets}
    incoming: dict[str, set[str]] = {}  # target -> {sources}

    for edge in graph.edges:
        outgoing.setdefault(edge.source, set()).add(edge.target)
        incoming.setdefault(edge.target, set()).add(edge.source)

    # Collect resource IDs by type
    ids_by_type: dict[str, list[str]] = {}
    for node in graph.nodes:
        ids_by_type.setdefault(node.resource_type, []).append(node.logical_id)

    # --- Detect async pipelines ---
    patterns.extend(_detect_async_pipelines(ids_by_type, outgoing, incoming, type_by_id))

    # --- Detect event-driven flows ---
    patterns.extend(_detect_event_driven(ids_by_type, outgoing, incoming, type_by_id))

    # --- Detect request-response chains ---
    patterns.extend(_detect_request_response(ids_by_type, outgoing, incoming, type_by_id))

    return patterns


def _has_edge(a: str, b: str, outgoing: dict[str, set[str]], incoming: dict[str, set[str]]) -> bool:
    """Check if there is any edge connecting a and b (in either direction)."""
    return b in outgoing.get(a, set()) or a in outgoing.get(b, set())


def _detect_async_pipelines(
    ids_by_type: dict[str, list[str]],
    outgoing: dict[str, set[str]],
    incoming: dict[str, set[str]],
    type_by_id: dict[str, str],
) -> list[ArchPattern]:
    """Detect async pipeline patterns: SQS → Lambda, SNS → SQS → Lambda."""
    patterns: list[ArchPattern] = []
    seen: set[tuple[str, ...]] = set()

    sqs_ids = ids_by_type.get(_SQS_QUEUE, [])
    sns_ids = ids_by_type.get(_SNS_TOPIC, [])
    lambda_ids = ids_by_type.get(_LAMBDA_FUNCTION, [])

    # Pattern: SQS → Lambda (direct)
    for sqs_id in sqs_ids:
        for lambda_id in lambda_ids:
            if _has_edge(sqs_id, lambda_id, outgoing, incoming):
                key = tuple(sorted([sqs_id, lambda_id]))
                if key not in seen:
                    seen.add(key)
                    patterns.append(ArchPattern(
                        pattern_type="async_pipeline",
                        resources=[sqs_id, lambda_id],
                        description=f"Async pipeline: {sqs_id} (SQS) → {lambda_id} (Lambda)",
                    ))

    # Pattern: SNS → SQS → Lambda
    for sns_id in sns_ids:
        for sqs_id in sqs_ids:
            if _has_edge(sns_id, sqs_id, outgoing, incoming):
                for lambda_id in lambda_ids:
                    if _has_edge(sqs_id, lambda_id, outgoing, incoming):
                        key = tuple(sorted([sns_id, sqs_id, lambda_id]))
                        if key not in seen:
                            seen.add(key)
                            patterns.append(ArchPattern(
                                pattern_type="async_pipeline",
                                resources=[sns_id, sqs_id, lambda_id],
                                description=(
                                    f"Async pipeline: {sns_id} (SNS) → "
                                    f"{sqs_id} (SQS) → {lambda_id} (Lambda)"
                                ),
                            ))

    return patterns


def _detect_event_driven(
    ids_by_type: dict[str, list[str]],
    outgoing: dict[str, set[str]],
    incoming: dict[str, set[str]],
    type_by_id: dict[str, str],
) -> list[ArchPattern]:
    """Detect event-driven patterns: EventBridge → Lambda, S3 → Lambda."""
    patterns: list[ArchPattern] = []

    eventbridge_ids = ids_by_type.get(_EVENTBRIDGE_RULE, [])
    s3_ids = ids_by_type.get(_S3_BUCKET, [])
    lambda_ids = ids_by_type.get(_LAMBDA_FUNCTION, [])

    # Pattern: EventBridge Rule → Lambda
    for eb_id in eventbridge_ids:
        for lambda_id in lambda_ids:
            if _has_edge(eb_id, lambda_id, outgoing, incoming):
                patterns.append(ArchPattern(
                    pattern_type="event_driven",
                    resources=[eb_id, lambda_id],
                    description=f"Event-driven: {eb_id} (EventBridge) → {lambda_id} (Lambda)",
                ))

    # Pattern: S3 → Lambda (event notifications)
    for s3_id in s3_ids:
        for lambda_id in lambda_ids:
            if _has_edge(s3_id, lambda_id, outgoing, incoming):
                patterns.append(ArchPattern(
                    pattern_type="event_driven",
                    resources=[s3_id, lambda_id],
                    description=f"Event-driven: {s3_id} (S3) → {lambda_id} (Lambda)",
                ))

    return patterns


def _detect_request_response(
    ids_by_type: dict[str, list[str]],
    outgoing: dict[str, set[str]],
    incoming: dict[str, set[str]],
    type_by_id: dict[str, str],
) -> list[ArchPattern]:
    """Detect request-response chains: API Gateway → Lambda → DynamoDB."""
    patterns: list[ArchPattern] = []

    apigw_ids = ids_by_type.get(_APIGW_REST_API, []) + ids_by_type.get(_APIGW_V2_API, [])
    lambda_ids = ids_by_type.get(_LAMBDA_FUNCTION, [])
    dynamodb_ids = ids_by_type.get(_DYNAMODB_TABLE, [])

    # Pattern: API Gateway → Lambda → DynamoDB
    for api_id in apigw_ids:
        for lambda_id in lambda_ids:
            if _has_edge(api_id, lambda_id, outgoing, incoming):
                for ddb_id in dynamodb_ids:
                    if _has_edge(lambda_id, ddb_id, outgoing, incoming):
                        patterns.append(ArchPattern(
                            pattern_type="request_response",
                            resources=[api_id, lambda_id, ddb_id],
                            description=(
                                f"Request-response: {api_id} (API Gateway) → "
                                f"{lambda_id} (Lambda) → {ddb_id} (DynamoDB)"
                            ),
                        ))

    return patterns

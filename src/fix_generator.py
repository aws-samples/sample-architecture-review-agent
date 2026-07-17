"""Fix generator for architecture review findings.

Generates CloudFormation code fixes matching the input template format (YAML or JSON).
For static findings, uses the rule's fix_hint plus template context.
For semantic findings, uses the suggested_fix field.
Findings requiring manual decisions get code=None with a descriptive explanation.
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from src.models import (
    Fix,
    ResourceGraph,
    ResourceNode,
    Rule,
    SemanticFinding,
    StaticFinding,
)


# Keywords that indicate a finding requires manual intervention
_MANUAL_KEYWORDS = [
    "choose between",
    "manual",
    "requires external",
    "consult",
    "depends on your",
    "architectural decision",
    "evaluate",
    "consider whether",
]


def generate_fixes(
    findings: list[StaticFinding | SemanticFinding],
    graph: ResourceGraph,
    input_format: str,
    rules: list[Any] | None = None,
) -> dict[str, Fix]:
    """Generate code fixes for each finding.

    Args:
        findings: Combined static + semantic findings.
        graph: Original resource graph for context.
        input_format: Output format matching the input template ("yaml" or "json").
        rules: Optional list of Rule objects for fix_hint lookup.

    Returns:
        Dict mapping finding identifier (rule_id for static, or index-based
        key for semantic) → Fix.
    """
    fixes: dict[str, Fix] = {}
    # Build a lookup of logical_id → ResourceNode for context
    node_map: dict[str, ResourceNode] = {
        node.logical_id: node for node in graph.nodes
    }

    # Build rule lookup for fix_hint access
    rule_map: dict[str, Any] = {}
    if rules:
        for rule in rules:
            rule_map[rule.id] = rule

    semantic_index = 0
    for finding in findings:
        if isinstance(finding, StaticFinding):
            key = finding.rule_id
            fix = _generate_static_fix(
                finding, node_map, input_format, rule_map
            )
        else:
            key = f"semantic-{semantic_index}"
            semantic_index += 1
            fix = _generate_semantic_fix(finding, node_map, input_format)
        fixes[key] = fix

    return fixes


def _generate_static_fix(
    finding: StaticFinding,
    node_map: dict[str, ResourceNode],
    input_format: str,
    rule_map: dict[str, Any] | None = None,
) -> Fix:
    """Generate a fix for a static analysis finding using the rule's fix_hint.

    Uses the fix_hint text and the resource's existing properties to produce
    a CloudFormation snippet showing the property addition/modification.
    """
    # Look up fix_hint from the rule if available
    fix_hint = _extract_fix_hint(finding, rule_map)

    # Check if this requires manual intervention
    if _requires_manual_fix(fix_hint):
        return Fix(
            description=fix_hint,
            code=None,
        )

    # Get the affected resource node for context
    node = node_map.get(finding.resource_logical_id)
    if node is None:
        return Fix(
            description=fix_hint if fix_hint else finding.description,
            code=None,
        )

    # Generate a code snippet based on the fix_hint and resource context
    snippet = _build_static_fix_snippet(finding, node, fix_hint)
    if snippet is None:
        return Fix(description=fix_hint, code=None)

    code = _format_snippet(snippet, input_format)
    return Fix(description=fix_hint, code=code)


def _generate_semantic_fix(
    finding: SemanticFinding,
    node_map: dict[str, ResourceNode],
    input_format: str,
) -> Fix:
    """Generate a fix for a semantic analysis finding using suggested_fix."""
    suggested_fix = finding.suggested_fix

    if not suggested_fix:
        return Fix(
            description=finding.description,
            code=None,
        )

    # Check if this requires manual intervention
    if _requires_manual_fix(suggested_fix):
        return Fix(
            description=suggested_fix,
            code=None,
        )

    # Get the affected resource node for context
    node = node_map.get(finding.resource_logical_id)
    if node is None:
        return Fix(
            description=suggested_fix,
            code=None,
        )

    # Generate a code snippet from the suggested_fix
    snippet = _build_semantic_fix_snippet(finding, node, suggested_fix)
    if snippet is None:
        return Fix(description=suggested_fix, code=None)

    code = _format_snippet(snippet, input_format)
    return Fix(description=suggested_fix, code=code)


def _extract_fix_hint(
    finding: StaticFinding, rule_map: dict[str, Any] | None = None
) -> str:
    """Extract the fix hint text for a static finding.

    Looks up the rule's fix_hint from the rule_map if available.
    Falls back to the finding description if no rule_map provided.
    """
    if rule_map and finding.rule_id in rule_map:
        rule = rule_map[finding.rule_id]
        if hasattr(rule, "fix_hint") and rule.fix_hint:
            return rule.fix_hint
    return finding.description


def _requires_manual_fix(text: str) -> bool:
    """Check if a fix description indicates manual intervention is needed."""
    lower_text = text.lower()
    return any(keyword in lower_text for keyword in _MANUAL_KEYWORDS)


def _build_static_fix_snippet(
    finding: StaticFinding,
    node: ResourceNode,
    fix_hint: str,
) -> dict[str, Any] | None:
    """Build a CloudFormation snippet for a static finding.

    Generates property additions/modifications for the affected resource
    based on the fix_hint and resource type.
    """
    resource_type = node.resource_type
    logical_id = node.logical_id

    # Generate fix based on common rule patterns
    fix_properties = _generate_properties_from_hint(
        finding.rule_id, resource_type, fix_hint, node.properties
    )

    if fix_properties is None:
        return None

    # Build the snippet showing the resource with the fix applied
    return {
        logical_id: {
            "Type": resource_type,
            "Properties": fix_properties,
        }
    }


def _build_semantic_fix_snippet(
    finding: SemanticFinding,
    node: ResourceNode,
    suggested_fix: str,
) -> dict[str, Any] | None:
    """Build a CloudFormation snippet for a semantic finding.

    Uses the suggested_fix text to determine what property or resource
    changes are needed.
    """
    logical_id = node.logical_id
    resource_type = node.resource_type

    # Parse the suggested fix to determine changes
    fix_properties = _parse_suggested_fix(
        suggested_fix, resource_type, node.properties
    )

    if fix_properties is None:
        return None

    return {
        logical_id: {
            "Type": resource_type,
            "Properties": fix_properties,
        }
    }


def _generate_properties_from_hint(
    rule_id: str,
    resource_type: str,
    fix_hint: str,
    existing_properties: dict[str, Any],
) -> dict[str, Any] | None:
    """Generate fix properties based on rule ID and resource type.

    Uses known patterns for common AWS resource types and security rules.
    Returns a dict of properties to add/modify, or None if cannot determine.
    """
    # Map of rule_id prefixes to fix generators
    fix_map = _get_fix_generators()

    # Try exact rule_id match first
    if rule_id in fix_map:
        return fix_map[rule_id](resource_type, existing_properties)

    # Try resource-type based generation from fix_hint keywords
    return _generate_from_hint_keywords(
        fix_hint, resource_type, existing_properties
    )


def _get_fix_generators() -> dict[str, Any]:
    """Return mapping of rule IDs to fix generator functions."""
    return {
        "SEC-004": _fix_s3_encryption,
        "SEC-005": _fix_dynamodb_encryption,
        "SEC-006": _fix_ebs_encryption,
        "SEC-007": _fix_rds_encryption,
        "SEC-010": _fix_s3_public_access,
        "SEC-011": _fix_s3_versioning,
        "REL-001": _fix_multi_az,
        "REL-004": _fix_backup,
    }


def _fix_s3_encryption(
    resource_type: str, existing_properties: dict[str, Any]
) -> dict[str, Any]:
    """Generate fix for S3 bucket encryption."""
    props = dict(existing_properties)
    props["BucketEncryption"] = {
        "ServerSideEncryptionConfiguration": [
            {
                "ServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                }
            }
        ]
    }
    return props


def _fix_dynamodb_encryption(
    resource_type: str, existing_properties: dict[str, Any]
) -> dict[str, Any]:
    """Generate fix for DynamoDB table encryption."""
    props = dict(existing_properties)
    props["SSESpecification"] = {
        "SSEEnabled": True,
        "SSEType": "KMS",
    }
    return props


def _fix_ebs_encryption(
    resource_type: str, existing_properties: dict[str, Any]
) -> dict[str, Any]:
    """Generate fix for EBS volume encryption."""
    props = dict(existing_properties)
    if resource_type == "AWS::EC2::Volume":
        props["Encrypted"] = True
    elif resource_type == "AWS::EC2::Instance":
        # Add encryption to block device mappings
        bdm = props.get("BlockDeviceMappings", [])
        if not bdm:
            bdm = [
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {"Encrypted": True, "VolumeType": "gp3"},
                }
            ]
        else:
            for mapping in bdm:
                ebs = mapping.get("Ebs", {})
                ebs["Encrypted"] = True
                mapping["Ebs"] = ebs
        props["BlockDeviceMappings"] = bdm
    return props


def _fix_rds_encryption(
    resource_type: str, existing_properties: dict[str, Any]
) -> dict[str, Any]:
    """Generate fix for RDS encryption."""
    props = dict(existing_properties)
    props["StorageEncrypted"] = True
    return props


def _fix_s3_public_access(
    resource_type: str, existing_properties: dict[str, Any]
) -> dict[str, Any]:
    """Generate fix for S3 public access block."""
    props = dict(existing_properties)
    props["PublicAccessBlockConfiguration"] = {
        "BlockPublicAcls": True,
        "BlockPublicPolicy": True,
        "IgnorePublicAcls": True,
        "RestrictPublicBuckets": True,
    }
    return props


def _fix_s3_versioning(
    resource_type: str, existing_properties: dict[str, Any]
) -> dict[str, Any]:
    """Generate fix for S3 versioning."""
    props = dict(existing_properties)
    props["VersioningConfiguration"] = {"Status": "Enabled"}
    return props


def _fix_multi_az(
    resource_type: str, existing_properties: dict[str, Any]
) -> dict[str, Any]:
    """Generate fix for Multi-AZ deployment."""
    props = dict(existing_properties)
    props["MultiAZ"] = True
    return props


def _fix_backup(
    resource_type: str, existing_properties: dict[str, Any]
) -> dict[str, Any]:
    """Generate fix for backup configuration."""
    props = dict(existing_properties)
    if resource_type in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
        props["BackupRetentionPeriod"] = 7
    elif resource_type == "AWS::DynamoDB::Table":
        props["PointInTimeRecoverySpecification"] = {
            "PointInTimeRecoveryEnabled": True,
        }
    return props


def _generate_from_hint_keywords(
    fix_hint: str,
    resource_type: str,
    existing_properties: dict[str, Any],
) -> dict[str, Any] | None:
    """Generate fix properties by parsing keywords from the fix_hint.

    Falls back to keyword-based generation when no exact rule match exists.
    """
    hint_lower = fix_hint.lower()
    props = dict(existing_properties)

    # Encryption-related hints
    if "encrypt" in hint_lower:
        if "s3" in resource_type.lower() or "bucket" in resource_type.lower():
            return _fix_s3_encryption(resource_type, existing_properties)
        if "dynamo" in resource_type.lower():
            return _fix_dynamodb_encryption(resource_type, existing_properties)
        if "rds" in resource_type.lower() or "db" in resource_type.lower():
            return _fix_rds_encryption(resource_type, existing_properties)
        if "volume" in resource_type.lower() or "ec2" in resource_type.lower():
            return _fix_ebs_encryption(resource_type, existing_properties)
        # Generic encryption
        props["Encrypted"] = True
        return props

    # Logging-related hints
    if "log" in hint_lower or "access log" in hint_lower:
        if "s3" in resource_type.lower() or "bucket" in resource_type.lower():
            props["LoggingConfiguration"] = {
                "DestinationBucketName": {"Ref": "LoggingBucket"},
            }
            return props
        if "lambda" in resource_type.lower():
            props["TracingConfig"] = {"Mode": "Active"}
            return props

    # Versioning hints
    if "version" in hint_lower:
        if "s3" in resource_type.lower() or "bucket" in resource_type.lower():
            return _fix_s3_versioning(resource_type, existing_properties)

    # Public access hints
    if "public" in hint_lower and "block" in hint_lower:
        return _fix_s3_public_access(resource_type, existing_properties)

    # Backup/retention hints
    if "backup" in hint_lower or "retention" in hint_lower:
        return _fix_backup(resource_type, existing_properties)

    # Multi-AZ hints
    if "multi-az" in hint_lower or "multi az" in hint_lower:
        return _fix_multi_az(resource_type, existing_properties)

    # Cannot determine fix from hint
    return None


def _parse_suggested_fix(
    suggested_fix: str,
    resource_type: str,
    existing_properties: dict[str, Any],
) -> dict[str, Any] | None:
    """Parse a semantic finding's suggested_fix to generate properties.

    Uses keyword analysis on the suggested fix text to determine
    appropriate property changes.
    """
    return _generate_from_hint_keywords(
        suggested_fix, resource_type, existing_properties
    )


def _format_snippet(snippet: dict[str, Any], input_format: str) -> str:
    """Format a CloudFormation snippet as YAML or JSON string.

    Args:
        snippet: Dict representing the CloudFormation resource snippet.
        input_format: "yaml" or "json".

    Returns:
        Formatted string in the specified format.
    """
    if input_format == "json":
        return json.dumps(snippet, indent=2)
    else:
        return yaml.dump(snippet, default_flow_style=False, sort_keys=False)

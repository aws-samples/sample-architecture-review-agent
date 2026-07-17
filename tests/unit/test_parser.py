"""Unit tests for the template parser module."""

import json

import pytest
import yaml

from src.models import (
    EmptyTemplateError,
    InvalidFormatError,
    ParseError,
    ResourceEdge,
    ResourceGraph,
    ResourceLimitError,
    ResourceNode,
)
from src.parser import parse_template


# ---------------------------------------------------------------------------
# Format validation
# ---------------------------------------------------------------------------


class TestFormatValidation:
    def test_valid_format_cloudformation(self):
        template = yaml.dump({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}})
        result = parse_template(template, "cloudformation")
        assert isinstance(result, ResourceGraph)

    def test_invalid_format_uppercase(self):
        with pytest.raises(InvalidFormatError) as exc_info:
            parse_template("Resources: {}", "CloudFormation")
        assert exc_info.value.format_value == "CloudFormation"

    def test_invalid_format_terraform(self):
        with pytest.raises(InvalidFormatError):
            parse_template("Resources: {}", "terraform")

    def test_invalid_format_empty(self):
        with pytest.raises(InvalidFormatError):
            parse_template("Resources: {}", "")


# ---------------------------------------------------------------------------
# Format auto-detection
# ---------------------------------------------------------------------------


class TestFormatAutoDetection:
    def test_json_detected_by_leading_brace(self):
        template = json.dumps({
            "Resources": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}}
        })
        result = parse_template(template, "cloudformation")
        assert result.template_format == "json"

    def test_json_detected_with_leading_whitespace(self):
        template = "   \n  " + json.dumps({
            "Resources": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}}
        })
        result = parse_template(template, "cloudformation")
        assert result.template_format == "json"

    def test_yaml_detected_when_no_brace(self):
        template = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n"
        result = parse_template(template, "cloudformation")
        assert result.template_format == "yaml"

    def test_yaml_with_aws_header(self):
        template = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n"
        result = parse_template(template, "cloudformation")
        assert result.template_format == "yaml"


# ---------------------------------------------------------------------------
# Parse errors
# ---------------------------------------------------------------------------


class TestParseErrors:
    def test_invalid_json_raises_parse_error(self):
        with pytest.raises(ParseError) as exc_info:
            parse_template("{invalid json", "cloudformation")
        assert exc_info.value.line_number >= 1
        assert exc_info.value.description != ""

    def test_invalid_yaml_raises_parse_error(self):
        with pytest.raises(ParseError) as exc_info:
            parse_template("key: [unclosed", "cloudformation")
        assert exc_info.value.line_number >= 1
        assert exc_info.value.description != ""


# ---------------------------------------------------------------------------
# CloudFormation shorthand intrinsic tags (!GetAtt, !Ref, !Sub, ...)
# ---------------------------------------------------------------------------


class TestCfnShorthandTags:
    """The parser must accept CFN shorthand YAML tags, not just longhand."""

    def test_getatt_shorthand_creates_edge(self):
        template = """
Resources:
  MyFunction:
    Type: AWS::Lambda::Function
    Properties:
      Role: !GetAtt MyRole.Arn
  MyRole:
    Type: AWS::IAM::Role
    Properties: {}
"""
        graph = parse_template(template, "cloudformation")
        assert len(graph.nodes) == 2
        getatt_edges = [e for e in graph.edges if e.reference_type == "Fn::GetAtt"]
        assert any(e.source == "MyFunction" and e.target == "MyRole"
                   and e.attribute == "Arn" for e in getatt_edges)

    def test_ref_and_sub_shorthand_parse(self):
        template = """
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties: {}
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Environment:
        Variables:
          Q: !Ref Queue
          ARN: !Sub "arn:aws:sqs:${Queue}"
"""
        graph = parse_template(template, "cloudformation")
        assert len(graph.nodes) == 2
        types = {e.reference_type for e in graph.edges}
        assert "Ref" in types
        assert "Fn::Sub" in types


# ---------------------------------------------------------------------------
# Empty template
# ---------------------------------------------------------------------------


class TestEmptyTemplate:
    def test_no_resources_key(self):
        template = yaml.dump({"AWSTemplateFormatVersion": "2010-09-09"})
        with pytest.raises(EmptyTemplateError):
            parse_template(template, "cloudformation")

    def test_empty_resources_dict(self):
        template = yaml.dump({"Resources": {}})
        with pytest.raises(EmptyTemplateError):
            parse_template(template, "cloudformation")

    def test_resources_is_none(self):
        template = "Resources:\n"
        with pytest.raises(EmptyTemplateError):
            parse_template(template, "cloudformation")


# ---------------------------------------------------------------------------
# Resource limit
# ---------------------------------------------------------------------------


class TestResourceLimit:
    def test_201_resources_raises_limit_error(self):
        resources = {f"Resource{i}": {"Type": "AWS::S3::Bucket", "Properties": {}} for i in range(201)}
        template = json.dumps({"Resources": resources})
        with pytest.raises(ResourceLimitError):
            parse_template(template, "cloudformation")

    def test_200_resources_is_allowed(self):
        resources = {f"Resource{i}": {"Type": "AWS::S3::Bucket", "Properties": {}} for i in range(200)}
        template = json.dumps({"Resources": resources})
        result = parse_template(template, "cloudformation")
        assert len(result.nodes) == 200


# ---------------------------------------------------------------------------
# Node extraction
# ---------------------------------------------------------------------------


class TestNodeExtraction:
    def test_single_resource(self):
        template = yaml.dump({
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": "test-bucket"},
                }
            }
        })
        result = parse_template(template, "cloudformation")
        assert len(result.nodes) == 1
        assert result.nodes[0].logical_id == "MyBucket"
        assert result.nodes[0].resource_type == "AWS::S3::Bucket"
        assert result.nodes[0].properties == {"BucketName": "test-bucket"}

    def test_multiple_resources(self):
        template = yaml.dump({
            "Resources": {
                "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
                "Function": {"Type": "AWS::Lambda::Function", "Properties": {"Runtime": "python3.13"}},
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        assert len(result.nodes) == 3
        logical_ids = {n.logical_id for n in result.nodes}
        assert logical_ids == {"Bucket", "Function", "Queue"}

    def test_resource_without_properties(self):
        template = yaml.dump({
            "Resources": {
                "MyBucket": {"Type": "AWS::S3::Bucket"}
            }
        })
        result = parse_template(template, "cloudformation")
        assert result.nodes[0].properties == {}


# ---------------------------------------------------------------------------
# Edge extraction - Ref
# ---------------------------------------------------------------------------


class TestRefEdges:
    def test_ref_creates_edge(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {"Environment": {"Variables": {"BUCKET": {"Ref": "MyBucket"}}}},
                },
                "MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        ref_edges = [e for e in result.edges if e.reference_type == "Ref"]
        assert len(ref_edges) == 1
        assert ref_edges[0].source == "MyFunction"
        assert ref_edges[0].target == "MyBucket"

    def test_ref_to_nonexistent_resource_ignored(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {"Role": {"Ref": "NonExistent"}},
                },
            }
        })
        result = parse_template(template, "cloudformation")
        assert len(result.edges) == 0

    def test_ref_to_pseudo_parameter_ignored(self):
        """Refs to AWS pseudo-parameters like AWS::StackName are not resources."""
        template = yaml.dump({
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": {"Ref": "AWS::StackName"}},
                },
            }
        })
        result = parse_template(template, "cloudformation")
        assert len(result.edges) == 0


# ---------------------------------------------------------------------------
# Edge extraction - Fn::GetAtt
# ---------------------------------------------------------------------------


class TestGetAttEdges:
    def test_getatt_list_form(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {"Role": {"Fn::GetAtt": ["MyRole", "Arn"]}},
                },
                "MyRole": {"Type": "AWS::IAM::Role", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        att_edges = [e for e in result.edges if e.reference_type == "Fn::GetAtt"]
        assert len(att_edges) == 1
        assert att_edges[0].source == "MyFunction"
        assert att_edges[0].target == "MyRole"
        assert att_edges[0].attribute == "Arn"

    def test_getatt_string_form(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {"Role": {"Fn::GetAtt": "MyRole.Arn"}},
                },
                "MyRole": {"Type": "AWS::IAM::Role", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        att_edges = [e for e in result.edges if e.reference_type == "Fn::GetAtt"]
        assert len(att_edges) == 1
        assert att_edges[0].target == "MyRole"
        assert att_edges[0].attribute == "Arn"


# ---------------------------------------------------------------------------
# Edge extraction - Fn::Sub
# ---------------------------------------------------------------------------


class TestSubEdges:
    def test_sub_string_form(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {
                            "Variables": {"URL": {"Fn::Sub": "https://${MyApi}.example.com"}}
                        }
                    },
                },
                "MyApi": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        sub_edges = [e for e in result.edges if e.reference_type == "Fn::Sub"]
        assert len(sub_edges) == 1
        assert sub_edges[0].source == "MyFunction"
        assert sub_edges[0].target == "MyApi"

    def test_sub_list_form(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Code": {"Fn::Sub": ["arn:aws:s3:::${MyBucket}/*", {}]}
                    },
                },
                "MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        sub_edges = [e for e in result.edges if e.reference_type == "Fn::Sub"]
        assert len(sub_edges) == 1
        assert sub_edges[0].target == "MyBucket"

    def test_sub_variable_override_excluded(self):
        """Variables explicitly overridden in the second arg should not create edges."""
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Code": {"Fn::Sub": ["${MyBucket}", {"MyBucket": "override-value"}]}
                    },
                },
                "MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        sub_edges = [e for e in result.edges if e.reference_type == "Fn::Sub"]
        assert len(sub_edges) == 0

    def test_sub_multiple_references(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Code": {"Fn::Sub": "${BucketA}-${BucketB}"}
                    },
                },
                "BucketA": {"Type": "AWS::S3::Bucket", "Properties": {}},
                "BucketB": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        sub_edges = [e for e in result.edges if e.reference_type == "Fn::Sub"]
        assert len(sub_edges) == 2
        targets = {e.target for e in sub_edges}
        assert targets == {"BucketA", "BucketB"}


# ---------------------------------------------------------------------------
# Edge extraction - DependsOn
# ---------------------------------------------------------------------------


class TestDependsOnEdges:
    def test_depends_on_string(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "DependsOn": "MyBucket",
                    "Properties": {},
                },
                "MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        dep_edges = [e for e in result.edges if e.reference_type == "DependsOn"]
        assert len(dep_edges) == 1
        assert dep_edges[0].source == "MyFunction"
        assert dep_edges[0].target == "MyBucket"

    def test_depends_on_list(self):
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "DependsOn": ["BucketA", "BucketB"],
                    "Properties": {},
                },
                "BucketA": {"Type": "AWS::S3::Bucket", "Properties": {}},
                "BucketB": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        dep_edges = [e for e in result.edges if e.reference_type == "DependsOn"]
        assert len(dep_edges) == 2
        targets = {e.target for e in dep_edges}
        assert targets == {"BucketA", "BucketB"}


# ---------------------------------------------------------------------------
# Patterns left empty
# ---------------------------------------------------------------------------


class TestPatternsEmpty:
    def test_patterns_always_empty(self):
        template = yaml.dump({
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "Function": {"Type": "AWS::Lambda::Function", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        assert result.patterns == []


# ---------------------------------------------------------------------------
# Edge deduplication
# ---------------------------------------------------------------------------


class TestEdgeDeduplication:
    def test_duplicate_ref_not_duplicated(self):
        """Multiple Refs to the same target from the same source should produce one edge."""
        template = yaml.dump({
            "Resources": {
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "EnvA": {"Ref": "MyBucket"},
                        "EnvB": {"Ref": "MyBucket"},
                    },
                },
                "MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        ref_edges = [e for e in result.edges if e.reference_type == "Ref"]
        assert len(ref_edges) == 1

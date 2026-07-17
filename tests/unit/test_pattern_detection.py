"""Unit tests for architectural pattern detection in the parser module."""

import json

import yaml

from src.models import ArchPattern, ResourceGraph
from src.parser import detect_patterns, parse_template


# ---------------------------------------------------------------------------
# Async Pipeline Detection
# ---------------------------------------------------------------------------


class TestAsyncPipelineDetection:
    """Tests for async pipeline pattern: SQS → Lambda, SNS → SQS → Lambda."""

    def test_sqs_to_lambda_via_event_source(self):
        """Lambda referencing an SQS queue should detect async pipeline."""
        template = yaml.dump({
            "Resources": {
                "MyQueue": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {
                            "Variables": {"QUEUE_URL": {"Ref": "MyQueue"}}
                        }
                    },
                },
            }
        })
        result = parse_template(template, "cloudformation")
        async_patterns = [p for p in result.patterns if p.pattern_type == "async_pipeline"]
        assert len(async_patterns) == 1
        assert "MyQueue" in async_patterns[0].resources
        assert "MyFunction" in async_patterns[0].resources

    def test_sqs_to_lambda_via_getatt(self):
        """Lambda referencing SQS ARN via Fn::GetAtt should detect async pipeline."""
        template = yaml.dump({
            "Resources": {
                "OrderQueue": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "ProcessOrder": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {
                            "Variables": {"QUEUE_ARN": {"Fn::GetAtt": ["OrderQueue", "Arn"]}}
                        }
                    },
                },
            }
        })
        result = parse_template(template, "cloudformation")
        async_patterns = [p for p in result.patterns if p.pattern_type == "async_pipeline"]
        assert len(async_patterns) == 1
        assert set(async_patterns[0].resources) == {"OrderQueue", "ProcessOrder"}

    def test_sns_to_sqs_to_lambda_chain(self):
        """SNS → SQS → Lambda chain should detect async pipeline with all three resources.

        The SQS queue references the SNS topic (e.g., in its redrive policy or
        subscription config), and the Lambda references the SQS queue.
        """
        template = yaml.dump({
            "Resources": {
                "NotificationTopic": {"Type": "AWS::SNS::Topic", "Properties": {}},
                "BufferQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "Tags": [{"Key": "Source", "Value": {"Ref": "NotificationTopic"}}]
                    },
                },
                "ProcessFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {
                            "Variables": {"QUEUE_URL": {"Ref": "BufferQueue"}}
                        }
                    },
                },
            }
        })
        result = parse_template(template, "cloudformation")
        async_patterns = [p for p in result.patterns if p.pattern_type == "async_pipeline"]
        # Should detect the SNS → SQS → Lambda chain
        sns_sqs_lambda = [
            p for p in async_patterns
            if "NotificationTopic" in p.resources and "BufferQueue" in p.resources and "ProcessFunction" in p.resources
        ]
        assert len(sns_sqs_lambda) == 1
        assert sns_sqs_lambda[0].resources == ["NotificationTopic", "BufferQueue", "ProcessFunction"]

    def test_no_async_pattern_without_connection(self):
        """SQS and Lambda without edges should not produce async pipeline pattern."""
        template = yaml.dump({
            "Resources": {
                "MyQueue": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {"Runtime": "python3.13"},
                },
            }
        })
        result = parse_template(template, "cloudformation")
        async_patterns = [p for p in result.patterns if p.pattern_type == "async_pipeline"]
        assert len(async_patterns) == 0

    def test_multiple_sqs_lambda_pairs(self):
        """Multiple SQS→Lambda connections should each produce a pattern."""
        template = yaml.dump({
            "Resources": {
                "QueueA": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "QueueB": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "FunctionA": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {"Environment": {"Variables": {"Q": {"Ref": "QueueA"}}}},
                },
                "FunctionB": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {"Environment": {"Variables": {"Q": {"Ref": "QueueB"}}}},
                },
            }
        })
        result = parse_template(template, "cloudformation")
        async_patterns = [p for p in result.patterns if p.pattern_type == "async_pipeline"]
        assert len(async_patterns) == 2


# ---------------------------------------------------------------------------
# Event-Driven Pattern Detection
# ---------------------------------------------------------------------------


class TestEventDrivenDetection:
    """Tests for event-driven pattern: EventBridge → Lambda, S3 → Lambda."""

    def test_eventbridge_to_lambda(self):
        """EventBridge rule targeting a Lambda should detect event-driven pattern."""
        template = yaml.dump({
            "Resources": {
                "ScheduleRule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Targets": [{"Arn": {"Fn::GetAtt": ["HandlerFunction", "Arn"]}}]
                    },
                },
                "HandlerFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {},
                },
            }
        })
        result = parse_template(template, "cloudformation")
        event_patterns = [p for p in result.patterns if p.pattern_type == "event_driven"]
        assert len(event_patterns) == 1
        assert "ScheduleRule" in event_patterns[0].resources
        assert "HandlerFunction" in event_patterns[0].resources

    def test_s3_to_lambda_event_notification(self):
        """S3 bucket with Lambda notification config should detect event-driven pattern."""
        template = yaml.dump({
            "Resources": {
                "UploadBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "NotificationConfiguration": {
                            "LambdaConfigurations": [
                                {"Function": {"Fn::GetAtt": ["ProcessUpload", "Arn"]}}
                            ]
                        }
                    },
                },
                "ProcessUpload": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {},
                },
            }
        })
        result = parse_template(template, "cloudformation")
        event_patterns = [p for p in result.patterns if p.pattern_type == "event_driven"]
        assert len(event_patterns) == 1
        assert "UploadBucket" in event_patterns[0].resources
        assert "ProcessUpload" in event_patterns[0].resources

    def test_s3_lambda_via_ref(self):
        """Lambda referencing an S3 bucket should detect event-driven pattern."""
        template = yaml.dump({
            "Resources": {
                "DataBucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
                "Processor": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {"Variables": {"BUCKET": {"Ref": "DataBucket"}}}
                    },
                },
            }
        })
        result = parse_template(template, "cloudformation")
        event_patterns = [p for p in result.patterns if p.pattern_type == "event_driven"]
        assert len(event_patterns) == 1
        assert set(event_patterns[0].resources) == {"DataBucket", "Processor"}

    def test_no_event_pattern_without_connection(self):
        """EventBridge and Lambda without edges should not produce event-driven pattern."""
        template = yaml.dump({
            "Resources": {
                "MyRule": {"Type": "AWS::Events::Rule", "Properties": {}},
                "MyFunction": {"Type": "AWS::Lambda::Function", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        event_patterns = [p for p in result.patterns if p.pattern_type == "event_driven"]
        assert len(event_patterns) == 0


# ---------------------------------------------------------------------------
# Request-Response Pattern Detection
# ---------------------------------------------------------------------------


class TestRequestResponseDetection:
    """Tests for request-response pattern: API Gateway → Lambda → DynamoDB."""

    def test_apigw_lambda_dynamodb_chain(self):
        """API Gateway → Lambda → DynamoDB chain should detect request-response pattern."""
        template = yaml.dump({
            "Resources": {
                "MyApi": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                "ApiHandler": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {
                            "Variables": {
                                "API": {"Ref": "MyApi"},
                                "TABLE": {"Ref": "UsersTable"},
                            }
                        }
                    },
                },
                "UsersTable": {"Type": "AWS::DynamoDB::Table", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        rr_patterns = [p for p in result.patterns if p.pattern_type == "request_response"]
        assert len(rr_patterns) == 1
        assert rr_patterns[0].resources == ["MyApi", "ApiHandler", "UsersTable"]

    def test_apigw_v2_lambda_dynamodb(self):
        """HTTP API (V2) → Lambda → DynamoDB should also detect request-response."""
        template = yaml.dump({
            "Resources": {
                "HttpApi": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {}},
                "Handler": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {
                            "Variables": {
                                "API_ID": {"Ref": "HttpApi"},
                                "TABLE_NAME": {"Ref": "ItemsTable"},
                            }
                        }
                    },
                },
                "ItemsTable": {"Type": "AWS::DynamoDB::Table", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        rr_patterns = [p for p in result.patterns if p.pattern_type == "request_response"]
        assert len(rr_patterns) == 1
        assert "HttpApi" in rr_patterns[0].resources
        assert "Handler" in rr_patterns[0].resources
        assert "ItemsTable" in rr_patterns[0].resources

    def test_no_request_response_without_dynamodb(self):
        """API Gateway → Lambda without DynamoDB should not produce request-response pattern."""
        template = yaml.dump({
            "Resources": {
                "MyApi": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                "Handler": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {"Variables": {"API": {"Ref": "MyApi"}}}
                    },
                },
            }
        })
        result = parse_template(template, "cloudformation")
        rr_patterns = [p for p in result.patterns if p.pattern_type == "request_response"]
        assert len(rr_patterns) == 0

    def test_no_request_response_without_apigw(self):
        """Lambda → DynamoDB without API Gateway should not produce request-response pattern."""
        template = yaml.dump({
            "Resources": {
                "Handler": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {"Variables": {"TABLE": {"Ref": "MyTable"}}}
                    },
                },
                "MyTable": {"Type": "AWS::DynamoDB::Table", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        rr_patterns = [p for p in result.patterns if p.pattern_type == "request_response"]
        assert len(rr_patterns) == 0


# ---------------------------------------------------------------------------
# Mixed Pattern Detection
# ---------------------------------------------------------------------------


class TestMixedPatterns:
    """Tests for templates containing multiple pattern types."""

    def test_template_with_all_three_patterns(self):
        """A complex template should detect all three pattern types."""
        template = yaml.dump({
            "Resources": {
                # Request-response chain
                "Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                "ApiHandler": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {
                            "Variables": {
                                "API": {"Ref": "Api"},
                                "TABLE": {"Ref": "DataTable"},
                            }
                        }
                    },
                },
                "DataTable": {"Type": "AWS::DynamoDB::Table", "Properties": {}},
                # Async pipeline
                "EventQueue": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "QueueProcessor": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {"Variables": {"QUEUE": {"Ref": "EventQueue"}}}
                    },
                },
                # Event-driven
                "CronRule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Targets": [{"Arn": {"Fn::GetAtt": ["CronHandler", "Arn"]}}]
                    },
                },
                "CronHandler": {"Type": "AWS::Lambda::Function", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")

        async_patterns = [p for p in result.patterns if p.pattern_type == "async_pipeline"]
        event_patterns = [p for p in result.patterns if p.pattern_type == "event_driven"]
        rr_patterns = [p for p in result.patterns if p.pattern_type == "request_response"]

        assert len(async_patterns) >= 1
        assert len(event_patterns) >= 1
        assert len(rr_patterns) >= 1

    def test_no_patterns_in_simple_template(self):
        """A template with only S3 buckets and no connections should have no patterns."""
        template = yaml.dump({
            "Resources": {
                "BucketA": {"Type": "AWS::S3::Bucket", "Properties": {}},
                "BucketB": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        })
        result = parse_template(template, "cloudformation")
        assert result.patterns == []


# ---------------------------------------------------------------------------
# detect_patterns function directly
# ---------------------------------------------------------------------------


class TestDetectPatternsFunction:
    """Tests for the detect_patterns function in isolation."""

    def test_detect_patterns_returns_list(self):
        """detect_patterns should always return a list."""
        graph = ResourceGraph(nodes=[], edges=[], patterns=[], template_format="yaml")
        result = detect_patterns(graph)
        assert isinstance(result, list)
        assert len(result) == 0

    def test_pattern_description_includes_logical_ids(self):
        """Pattern descriptions should include the involved resource logical IDs."""
        template = yaml.dump({
            "Resources": {
                "IngestQueue": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "Worker": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Environment": {"Variables": {"Q": {"Ref": "IngestQueue"}}}
                    },
                },
            }
        })
        result = parse_template(template, "cloudformation")
        async_patterns = [p for p in result.patterns if p.pattern_type == "async_pipeline"]
        assert len(async_patterns) == 1
        assert "IngestQueue" in async_patterns[0].description
        assert "Worker" in async_patterns[0].description

    def test_pattern_type_values(self):
        """All detected patterns should have valid pattern_type values."""
        template = yaml.dump({
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {"Environment": {"Variables": {"Q": {"Ref": "Queue"}}}},
                },
            }
        })
        result = parse_template(template, "cloudformation")
        valid_types = {"async_pipeline", "event_driven", "request_response"}
        for pattern in result.patterns:
            assert pattern.pattern_type in valid_types

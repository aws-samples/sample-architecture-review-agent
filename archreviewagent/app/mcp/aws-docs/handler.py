"""AWS Documentation MCP Tool Lambda Handler.

Implements search_documentation and read_documentation tools as a Lambda
function behind AgentCore Gateway.

Uses a curated mapping of AWS best-practice documentation URLs indexed by
service and security/reliability topics. This approach is reliable and fast
since it doesn't depend on external search APIs.
"""

from __future__ import annotations

import json
import logging
import re
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Curated AWS Documentation Index
# ---------------------------------------------------------------------------

_DOCS_INDEX = {
    "s3": {
        "encryption": {
            "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
            "title": "Setting default server-side encryption behavior for Amazon S3 buckets",
            "context": "Use server-side encryption with Amazon S3 managed keys (SSE-S3), AWS KMS keys (SSE-KMS), or customer-provided keys (SSE-C) to protect data at rest.",
        },
        "public access": {
            "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "title": "Blocking public access to your Amazon S3 storage",
            "context": "Use S3 Block Public Access to manage public access to S3 resources. Block Public Access settings override bucket policies and ACLs.",
        },
        "versioning": {
            "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
            "title": "Using versioning in S3 buckets",
            "context": "Versioning enables you to keep multiple variants of an object in the same bucket, protecting against accidental deletion or overwrite.",
        },
        "lifecycle": {
            "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html",
            "title": "Managing your storage lifecycle",
            "context": "Use lifecycle configuration rules to transition objects between storage classes and expire objects to optimize costs.",
        },
        "logging": {
            "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
            "title": "Logging requests using server access logging",
            "context": "Server access logging provides detailed records for requests made to a bucket, useful for security audits.",
        },
        "best practices": {
            "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
            "title": "Security best practices for Amazon S3",
            "context": "Recommendations for S3 security including encryption, access control, monitoring, and data protection.",
        },
    },
    "iam": {
        "wildcard": {
            "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "title": "Security best practices in IAM",
            "context": "Grant least privilege access. Instead of allowing broad actions, grant only the permissions required to perform a task.",
        },
        "least privilege": {
            "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "title": "Security best practices in IAM",
            "context": "Start with minimum permissions and grant additional permissions as necessary. Use IAM Access Analyzer to identify unused permissions.",
        },
        "administrator": {
            "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "title": "Security best practices in IAM",
            "context": "Do not use the AWS account root user or AdministratorAccess for everyday tasks. Create individual IAM roles with specific permissions.",
        },
        "role": {
            "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-service.html",
            "title": "Creating a role for an AWS service",
            "context": "Create service-linked roles with only the permissions the service needs. Each Lambda function should have its own dedicated execution role.",
        },
    },
    "lambda": {
        "timeout": {
            "url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-function-common.html",
            "title": "Configuring Lambda function options",
            "context": "Set timeout to the minimum value needed. Default is 3 seconds, maximum is 900 seconds. Avoid maximum timeout for API-facing functions.",
        },
        "dlq": {
            "url": "https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html",
            "title": "Asynchronous invocation",
            "context": "Configure a dead-letter queue or on-failure destination to capture events that fail all processing attempts.",
        },
        "vpc": {
            "url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html",
            "title": "Configuring a Lambda function to access resources in a VPC",
            "context": "Functions in a VPC need a NAT gateway for internet access. Use VPC endpoints for AWS services to reduce cost and latency.",
        },
        "memory": {
            "url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-memory.html",
            "title": "Configuring Lambda function memory",
            "context": "Memory allocation also determines CPU and network bandwidth. Use AWS Lambda Power Tuning to find the optimal configuration.",
        },
        "monitoring": {
            "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-monitoring.html",
            "title": "Monitoring and observability for AWS Lambda",
            "context": "Enable X-Ray tracing and structured logging. Use CloudWatch Lambda Insights for enhanced monitoring.",
        },
        "concurrency": {
            "url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html",
            "title": "Configuring reserved concurrency",
            "context": "Use reserved concurrency to guarantee availability and prevent one function from consuming all available concurrency.",
        },
        "best practices": {
            "url": "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html",
            "title": "Best practices for working with AWS Lambda functions",
            "context": "Follow best practices for function configuration, code, networking, and monitoring.",
        },
    },
    "dynamodb": {
        "encryption": {
            "url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
            "title": "DynamoDB encryption at rest",
            "context": "All DynamoDB tables are encrypted at rest. Choose between AWS owned key, AWS managed key, or customer managed key for control over key management.",
        },
        "backup": {
            "url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
            "title": "Point-in-time recovery for DynamoDB",
            "context": "Enable PITR to protect against accidental writes or deletes. Provides continuous backups of DynamoDB table data.",
        },
        "best practices": {
            "url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices.html",
            "title": "Best practices for designing and architecting with DynamoDB",
            "context": "Design tables for uniform workloads, use on-demand for unpredictable traffic, and enable encryption and backups.",
        },
    },
    "sqs": {
        "dlq": {
            "url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html",
            "title": "Amazon SQS dead-letter queues",
            "context": "Configure dead-letter queues to isolate and debug messages that fail processing. Set maxReceiveCount to control retry behavior.",
        },
        "encryption": {
            "url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
            "title": "Encryption at rest for Amazon SQS",
            "context": "Enable server-side encryption using SQS-managed keys (SSE-SQS) or AWS KMS keys (SSE-KMS) to protect message contents.",
        },
        "best practices": {
            "url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-best-practices.html",
            "title": "Best practices for Amazon SQS",
            "context": "Use dead-letter queues for failed messages, enable encryption, set appropriate visibility timeout, and monitor queue metrics.",
        },
    },
    "apigateway": {
        "throttling": {
            "url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html",
            "title": "Throttle API requests for better throughput",
            "context": "Configure throttling to protect backend services from traffic spikes. Set rate and burst limits per stage and method.",
        },
        "authentication": {
            "url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html",
            "title": "Controlling and managing access to a REST API",
            "context": "Use IAM authorization, Lambda authorizers, or Cognito user pools to control access to API Gateway endpoints.",
        },
        "logging": {
            "url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
            "title": "Setting up CloudWatch logging for a REST API",
            "context": "Enable execution logging and access logging to monitor API usage and debug integration issues.",
        },
    },
    "rds": {
        "encryption": {
            "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
            "title": "Encrypting Amazon RDS resources",
            "context": "Enable encryption at rest for RDS DB instances. Encryption must be set at creation time and cannot be added later.",
        },
        "multi-az": {
            "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html",
            "title": "Multi-AZ deployments for high availability",
            "context": "Multi-AZ provides enhanced availability and durability by automatically provisioning a standby replica in a different AZ.",
        },
        "backup": {
            "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
            "title": "Working with backups",
            "context": "Configure automated backups with appropriate retention period. Use manual snapshots for long-term retention.",
        },
    },
}


def lambda_handler(event: dict, context) -> dict:
    """Lambda entry point for AgentCore Gateway MCP tool invocation.

    The Gateway sends tool arguments directly as the event payload.
    """
    logger.info(f"Event received: {json.dumps(event)[:300]}")

    if "search_phrase" in event:
        return _handle_search(event)
    elif "url" in event:
        return _handle_read(event)
    else:
        return {"error": f"Cannot determine tool from arguments: {list(event.keys())}"}


def _handle_search(arguments: dict) -> dict:
    """Handle search_documentation tool call using curated docs index."""
    search_phrase = arguments.get("search_phrase", "").lower()
    limit = min(int(arguments.get("limit", 5)), 10)

    if not search_phrase:
        return {"error": "search_phrase is required"}

    results = []

    # Match against the curated index
    for service, topics in _DOCS_INDEX.items():
        if service in search_phrase:
            # Service matched — find best topic match
            for topic_key, doc in topics.items():
                if topic_key in search_phrase or _fuzzy_match(topic_key, search_phrase):
                    results.append({
                        "url": doc["url"],
                        "title": doc["title"],
                        "context": doc["context"],
                    })

    # If no specific topic matched but service did, return best practices
    if not results:
        for service, topics in _DOCS_INDEX.items():
            if service in search_phrase:
                if "best practices" in topics:
                    results.append({
                        "url": topics["best practices"]["url"],
                        "title": topics["best practices"]["title"],
                        "context": topics["best practices"]["context"],
                    })
                else:
                    # Return first available topic for the service
                    first_topic = next(iter(topics.values()))
                    results.append({
                        "url": first_topic["url"],
                        "title": first_topic["title"],
                        "context": first_topic["context"],
                    })

    # Fallback: return IAM best practices for security-related queries
    if not results and any(kw in search_phrase for kw in ["security", "permission", "access", "policy"]):
        iam_bp = _DOCS_INDEX["iam"]["least privilege"]
        results.append({
            "url": iam_bp["url"],
            "title": iam_bp["title"],
            "context": iam_bp["context"],
        })

    logger.info(f"Search returned {len(results)} results for: {search_phrase[:80]}")

    return {
        "search_results": results[:limit],
        "count": len(results[:limit]),
    }


def _handle_read(arguments: dict) -> dict:
    """Handle read_documentation tool call by fetching the page."""
    url = arguments.get("url", "")
    max_length = int(arguments.get("max_length", 5000))

    if not url:
        return {"error": "url is required"}

    if not url.startswith("https://docs.aws.amazon.com/"):
        return {"error": "URL must be from docs.aws.amazon.com"}

    try:
        req = Request(url, headers={"User-Agent": "AgentCore-ArchReview/1.0"})
        with urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8")

        content = _html_to_text(html)
        if len(content) > max_length:
            content = content[:max_length] + "\n\n[truncated]"

        return {"url": url, "content": content}

    except (URLError, TimeoutError) as exc:
        logger.warning(f"Failed to fetch doc page: {exc}")
        return {"error": f"Could not fetch documentation page: {exc}"}
    except Exception as exc:
        logger.error(f"Unexpected error reading doc: {exc}")
        return {"error": str(exc)}


def _fuzzy_match(topic_key: str, search_phrase: str) -> bool:
    """Check if a topic key fuzzy-matches the search phrase."""
    # Split topic key into words and check if most appear in the phrase
    words = topic_key.split()
    matches = sum(1 for w in words if w in search_phrase)
    return matches >= len(words) * 0.5


def _html_to_text(html: str) -> str:
    """Extract readable text from HTML."""
    # Remove script and style blocks
    content = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)
    content = re.sub(r"<style[^>]*>.*?</style>", "", content, flags=re.DOTALL)

    # Convert headers
    content = re.sub(
        r"<h([1-6])[^>]*>(.*?)</h\1>",
        lambda m: "\n" + "#" * int(m.group(1)) + " " + re.sub(r"<[^>]+>", "", m.group(2)) + "\n",
        content,
    )

    # Convert list items and paragraphs
    content = re.sub(r"<li[^>]*>", "\n- ", content)
    content = re.sub(r"<p[^>]*>", "\n\n", content)
    content = re.sub(r"<[^>]+>", "", content)
    content = re.sub(r"\n{3,}", "\n\n", content)
    content = re.sub(r"[ \t]+", " ", content)

    return content.strip()

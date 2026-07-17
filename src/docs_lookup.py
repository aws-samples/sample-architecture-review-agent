"""AWS Documentation lookup via AgentCore Gateway MCP tools.

Provides functions to search and retrieve AWS documentation through the
AgentCore Gateway, enriching architecture review findings with authoritative
best-practice guidance and links.

When the Gateway is configured and the MCP server target is reachable,
documentation lookups flow through:
  Agent → AgentCore Gateway (SigV4-signed HTTPS) → Lambda (aws-docs) → AWS Docs API

When the Gateway is not available (e.g., during local development), the
module falls back to direct AWS documentation search via HTTPS.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# Gateway URL is injected as an environment variable by the AgentCore deployment
GATEWAY_URL = os.getenv("AGENTCORE_GATEWAY_ARCHREVIEW_GATEWAY_URL", "")

# AWS Documentation Search API (public, no auth required)
_AWS_DOCS_SEARCH_URL = "https://docs.aws.amazon.com/search/doc-search.html"


def _search_aws_docs_direct(query: str, limit: int = 3) -> list[dict[str, str]]:
    """Search AWS documentation directly via the public search API.

    This is the fallback path when the AgentCore Gateway is not configured.

    Args:
        query: Search phrase.
        limit: Maximum results.

    Returns:
        List of dicts with url, title, context.
    """
    try:
        params = urlencode({
            "searchQuery": query,
            "is498": "true",
            "this_doc_guide": "",
        })
        url = f"{_AWS_DOCS_SEARCH_URL}?{params}"
        req = Request(url, headers={"Accept": "application/json"})

        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        results = []
        for item in data.get("items", [])[:limit]:
            results.append({
                "url": item.get("href", ""),
                "title": item.get("title", "").replace("<em>", "").replace("</em>", ""),
                "context": item.get("context", "").replace("<em>", "").replace("</em>", ""),
            })
        return results

    except (URLError, json.JSONDecodeError, KeyError, TimeoutError) as exc:
        logger.debug("Direct AWS docs search failed: %s", exc)
        return []


def _gateway_jsonrpc_call(
    tool_name: str, arguments: dict[str, Any]
) -> dict[str, Any] | None:
    """Make a single SigV4-signed MCP ``tools/call`` to the AgentCore Gateway.

    This is the single source of truth for Gateway request signing and
    transport. The Gateway exposes an MCP endpoint (JSON-RPC over HTTPS); for
    AWS_IAM auth, requests must be signed with SigV4 using the runtime's
    execution-role credentials.

    Args:
        tool_name: Full tool name (target___tool format,
            e.g. "aws-docs___search_documentation").
        arguments: Tool input arguments.

    Returns:
        The parsed JSON-RPC response dict — which contains either a ``result``
        key (success) or an ``error`` key (e.g. a policy denial). Returns None
        only on a transport-level failure (no gateway URL, no credentials,
        network error), where no JSON-RPC response was obtained.
    """
    if not GATEWAY_URL:
        return None

    try:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.session import Session as BotocoreSession

        # Build JSON-RPC request for MCP tools/call
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }).encode("utf-8")

        # Sign the request with SigV4 using the runtime's credentials
        session = BotocoreSession()
        credentials = session.get_credentials()
        if credentials is None:
            logger.debug("No AWS credentials available for SigV4 signing")
            return None

        frozen_credentials = credentials.get_frozen_credentials()
        region = os.getenv("AWS_REGION", "us-east-1")

        aws_request = AWSRequest(
            method="POST",
            url=GATEWAY_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        SigV4Auth(frozen_credentials, "bedrock-agentcore", region).add_auth(aws_request)

        # Make the signed HTTP request
        req = Request(
            GATEWAY_URL,
            data=payload,
            headers=dict(aws_request.headers),
            method="POST",
        )

        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))

    except Exception as exc:
        logger.debug("Gateway tool invocation failed: %s", exc)
        return None


def _invoke_gateway_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
    """Invoke a Gateway tool, returning the unwrapped tool payload on success.

    Convenience wrapper over `_gateway_jsonrpc_call` used by the documentation
    lookup path: it swallows errors (returning None) so callers can fall back
    to a direct HTTP search. To surface policy denials instead of hiding them,
    use `call_gateway_tool`.

    Returns:
        Tool response dict, or None if invocation fails (including policy denial).
    """
    response_data = _gateway_jsonrpc_call(tool_name, arguments)
    if response_data is None:
        return None

    # Extract the result from JSON-RPC response
    if "error" in response_data:
        logger.debug("Gateway returned error: %s", response_data["error"])
        return None

    result = response_data.get("result", {})

    # MCP tools/call returns content array
    content = result.get("content", [])
    if content and isinstance(content, list):
        for item in content:
            if item.get("type") == "text":
                text = item.get("text", "")
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return {"content": text}

    return result


def call_gateway_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Invoke a Gateway tool and return a structured allow/deny outcome.

    Unlike `_invoke_gateway_tool` (which returns None on any failure to enable
    silent fallback), this surfaces the Gateway's response verbatim so callers
    can demonstrate AgentCore Policy enforcement. When a Cedar policy forbids a
    tool, the Gateway returns a JSON-RPC error like::

        {"code": -32002, "message": "Tool Execution Denied: Tool call not
         allowed due to policy enforcement"}

    Args:
        tool_name: Full tool name (target___tool format,
            e.g. "infra-modifier___modify_infrastructure").
        arguments: Tool input arguments.

    Returns:
        One of:
        - {"status": "allowed", "result": <tool payload>}
        - {"status": "denied", "error": {"code": ..., "message": ...}}
        - {"status": "unavailable", "message": ...} when the Gateway is not
          configured or unreachable (no JSON-RPC response obtained).
    """
    response_data = _gateway_jsonrpc_call(tool_name, arguments)
    if response_data is None:
        return {
            "status": "unavailable",
            "message": "AgentCore Gateway is not configured or could not be reached.",
        }

    if "error" in response_data:
        return {"status": "denied", "error": response_data["error"]}

    result = response_data.get("result", {})

    # Unwrap the MCP content array to the tool's own payload when present.
    content = result.get("content", [])
    if content and isinstance(content, list):
        for item in content:
            if item.get("type") == "text":
                text = item.get("text", "")
                try:
                    return {"status": "allowed", "result": json.loads(text)}
                except json.JSONDecodeError:
                    return {"status": "allowed", "result": {"content": text}}

    return {"status": "allowed", "result": result}


def search_aws_docs(query: str, limit: int = 3) -> list[dict[str, str]]:
    """Search AWS documentation for relevant pages.

    Tries AgentCore Gateway first, falls back to direct API call.

    Args:
        query: Search phrase (e.g., "S3 bucket encryption best practices").
        limit: Maximum number of results to return.

    Returns:
        List of dicts with keys: url, title, context (snippet).
        Returns empty list if all methods fail.
    """
    # Try Gateway path first
    if GATEWAY_URL:
        result = _invoke_gateway_tool(
            "aws-docs___search_documentation",
            {"search_phrase": query, "limit": limit},
        )
        if result:
            search_results = result.get("search_results", [])
            docs = []
            for item in search_results:
                docs.append({
                    "url": item.get("url", ""),
                    "title": item.get("title", ""),
                    "context": item.get("context", ""),
                })
            if docs:
                return docs[:limit]

    # Fallback to direct search
    return _search_aws_docs_direct(query, limit)


def lookup_docs_for_finding(
    resource_type: str,
    finding_title: str,
    pillar: str,
) -> dict[str, Any]:
    """Look up AWS documentation relevant to a specific finding.

    Builds a search query from the resource type and finding context,
    searches AWS docs, and returns the top result with a link.

    Args:
        resource_type: AWS CloudFormation resource type (e.g., "AWS::S3::Bucket").
        finding_title: Title of the finding (e.g., "S3 Bucket Missing Encryption").
        pillar: Well-Architected pillar (e.g., "security").

    Returns:
        Dict with keys: url, title, context. Empty dict if lookup fails.
    """
    service_name = _extract_service_name(resource_type)
    query = f"{service_name} {finding_title} best practices"

    docs = search_aws_docs(query, limit=1)
    if docs:
        return docs[0]
    return {}


def enrich_findings_with_docs(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Enrich a list of findings with AWS documentation references.

    Only enriches critical and warning findings to avoid excessive API calls.

    Args:
        findings: List of finding dicts (must have 'severity', 'title', 'resource').

    Returns:
        Same list with 'doc_reference' key added where docs were found.
    """
    enriched_count = 0
    max_enrichments = 5  # Limit API calls per review

    for finding in findings:
        if enriched_count >= max_enrichments:
            break

        severity = finding.get("severity", "")
        if severity not in ("critical", "warning"):
            continue

        resource = finding.get("resource", "")
        title = finding.get("title", "")
        pillar = finding.get("pillar", "")

        # Extract resource type from display format "LogicalId (AWS::Type)"
        resource_type = ""
        if "(" in resource and ")" in resource:
            resource_type = resource.split("(")[-1].rstrip(")")

        doc_ref = lookup_docs_for_finding(resource_type, title, pillar)
        if doc_ref and doc_ref.get("url"):
            finding["doc_reference"] = doc_ref
            enriched_count += 1

    return findings


def _extract_service_name(resource_type: str) -> str:
    """Extract a human-readable service name from a CloudFormation resource type.

    Examples:
        "AWS::S3::Bucket" -> "S3"
        "AWS::Lambda::Function" -> "Lambda"
        "AWS::DynamoDB::Table" -> "DynamoDB"
    """
    if not resource_type:
        return ""
    parts = resource_type.split("::")
    if len(parts) >= 2:
        return parts[1]
    return resource_type

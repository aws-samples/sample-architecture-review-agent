"""Architecture Review Agent on Amazon Bedrock AgentCore Runtime.

A Strands-based agent that reviews CloudFormation templates against AWS
Well-Architected best practices. Well-Architected rules are seeded into
AgentCore Memory on startup. AWS documentation lookups and a (policy-denied)
remediation tool are reached through the AgentCore Gateway.
"""

from __future__ import annotations

import os
import sys
import json
import logging
from typing import Any

# Ensure 'src' package imports work in both local and deployed environments
_src_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_src_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
try:
    import src  # noqa: F401
except ImportError:
    import types
    src_module = types.ModuleType("src")
    src_module.__path__ = [_src_dir]
    sys.modules["src"] = src_module

from strands import Agent, tool
from bedrock_agentcore.runtime import BedrockAgentCoreApp

from src.models import (
    EmptyTemplateError,
    InvalidFormatError,
    InvalidPillarError,
    ParseError,
    ResourceLimitError,
)
from src.parser import parse_template
from src.static_analyzer import load_rules, run_static_analysis
from src.semantic_analyzer import run_semantic_analysis
from src.fix_generator import generate_fixes
from src.response_composer import compose_response
from src.docs_lookup import call_gateway_tool, enrich_findings_with_docs, search_aws_docs
from src.tracing import start_review_trace, trace_stage, clear_current_trace, trace_to_dict
from src.models import OrgRule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AgentCore Memory integration
# ---------------------------------------------------------------------------

MEMORY_ID = os.getenv("MEMORY_ARCHREVIEW_MEMORY_ID", "")
WA_RULES_NAMESPACE = "/rules/well-architected/"
ORG_RULES_NAMESPACE = "/rules/org/"


def _get_memory_client():
    """Get a boto3 client for AgentCore Memory operations."""
    import boto3
    return boto3.client("bedrock-agentcore", region_name=os.getenv("AWS_REGION", "us-east-1"))


def _load_wa_rules_from_memory() -> list[dict]:
    """Load Well-Architected rules from AgentCore Memory.

    Returns list of rule dicts, or empty list if memory unavailable.
    """
    if not MEMORY_ID:
        logger.warning("MEMORY_ID not set, loading rules from local file")
        return []

    try:
        client = _get_memory_client()
        response = client.retrieve_memory_records(
            memoryId=MEMORY_ID,
            namespace=WA_RULES_NAMESPACE,
            searchQuery="well-architected rules",
            topK=100,
        )
        records = response.get("memoryRecords", [])
        if records:
            logger.info(f"Loaded {len(records)} WA rules from AgentCore Memory")
            return [json.loads(r["content"]["text"]) for r in records]
        return []
    except Exception as exc:
        logger.warning(f"Failed to load WA rules from memory: {exc}")
        return []


def _seed_wa_rules_to_memory():
    """Seed Well-Architected rules into AgentCore Memory on first deployment.

    Checks if rules already exist; if not, loads from wa_rules.json and persists.
    """
    if not MEMORY_ID:
        logger.info("MEMORY_ID not set, skipping rule seeding")
        return

    try:
        client = _get_memory_client()
        # Check if rules already seeded
        response = client.list_memory_records(
            memoryId=MEMORY_ID,
            namespace=WA_RULES_NAMESPACE,
            maxResults=1,
        )
        if response.get("memoryRecords"):
            logger.info("WA rules already seeded in memory")
            return

        # Load from local file and seed to memory
        rules = load_rules()
        logger.info(f"Seeding {len(rules)} WA rules to AgentCore Memory...")

        import time
        records = []
        for rule in rules:
            rule_dict = {
                "id": rule.id,
                "pillar": rule.pillar,
                "category": rule.category,
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "resource_types": rule.resource_types,
                "check": rule.check,
                "fix_hint": rule.fix_hint,
            }
            records.append({
                "content": {"text": json.dumps(rule_dict)},
                "namespaces": [WA_RULES_NAMESPACE],
                "requestIdentifier": rule.id,
                "timestamp": time.time(),
            })

        # Batch create in chunks of 100
        for i in range(0, len(records), 100):
            batch = records[i:i+100]
            client.batch_create_memory_records(
                memoryId=MEMORY_ID,
                records=batch,
            )
        logger.info(f"Successfully seeded {len(rules)} WA rules to memory")

    except Exception as exc:
        logger.warning(f"Failed to seed WA rules to memory: {exc}")


# ---------------------------------------------------------------------------
# Built-in rules (fallback if memory unavailable)
# ---------------------------------------------------------------------------

_built_in_rules = load_rules()


# ---------------------------------------------------------------------------
# Org rules (loaded from file and seeded to memory)
# ---------------------------------------------------------------------------

_ORG_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "org_rules.json")


def _load_org_rules_from_file() -> list[OrgRule]:
    """Load organization rules from the local org_rules.json file."""
    try:
        with open(_ORG_RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = []
        for i, entry in enumerate(data.get("rules", [])):
            rules.append(OrgRule(
                rule_id=f"org-rule-{i+1:03d}",
                rule_text=entry["rule_text"],
                severity=entry["severity"],
                pillar=entry.get("pillar"),
            ))
        return rules
    except Exception as exc:
        logger.warning(f"Failed to load org rules from file: {exc}")
        return []


def _load_org_rules_from_memory() -> list[OrgRule]:
    """Load organization rules from AgentCore Memory.

    Returns list of OrgRule objects, or empty list if memory unavailable.
    """
    if not MEMORY_ID:
        return []

    try:
        client = _get_memory_client()
        response = client.retrieve_memory_records(
            memoryId=MEMORY_ID,
            namespace=ORG_RULES_NAMESPACE,
            searchQuery="organization rules",
            topK=100,
        )
        records = response.get("memoryRecords", [])
        if records:
            logger.info(f"Loaded {len(records)} org rules from AgentCore Memory")
            rules = []
            for r in records:
                data = json.loads(r["content"]["text"])
                rules.append(OrgRule(
                    rule_id=data.get("rule_id", ""),
                    rule_text=data["rule_text"],
                    severity=data["severity"],
                    pillar=data.get("pillar"),
                ))
            return rules
        return []
    except Exception as exc:
        logger.warning(f"Failed to load org rules from memory: {exc}")
        return []


def _seed_org_rules_to_memory():
    """Seed organization rules into AgentCore Memory on first deployment.

    Checks if org rules already exist; if not, loads from org_rules.json and persists.
    """
    if not MEMORY_ID:
        logger.info("MEMORY_ID not set, skipping org rule seeding")
        return

    try:
        client = _get_memory_client()
        # Check if org rules already seeded
        response = client.list_memory_records(
            memoryId=MEMORY_ID,
            namespace=ORG_RULES_NAMESPACE,
            maxResults=1,
        )
        if response.get("memoryRecords"):
            logger.info("Org rules already seeded in memory")
            return

        # Load from local file and seed to memory
        org_rules = _load_org_rules_from_file()
        if not org_rules:
            logger.info("No org rules found in org_rules.json, skipping seeding")
            return

        logger.info(f"Seeding {len(org_rules)} org rules to AgentCore Memory...")

        import time
        records = []
        for rule in org_rules:
            rule_dict = {
                "rule_id": rule.rule_id,
                "rule_text": rule.rule_text,
                "severity": rule.severity,
                "pillar": rule.pillar,
            }
            records.append({
                "content": {"text": json.dumps(rule_dict)},
                "namespaces": [ORG_RULES_NAMESPACE],
                "requestIdentifier": rule.rule_id,
                "timestamp": time.time(),
            })

        # Batch create in chunks of 100
        for i in range(0, len(records), 100):
            batch = records[i:i+100]
            client.batch_create_memory_records(
                memoryId=MEMORY_ID,
                records=batch,
            )
        logger.info(f"Successfully seeded {len(org_rules)} org rules to memory")

    except Exception as exc:
        logger.warning(f"Failed to seed org rules to memory: {exc}")


# Load org rules (prefer memory, fallback to file)
_org_rules: list[OrgRule] = _load_org_rules_from_memory() or _load_org_rules_from_file()


# ---------------------------------------------------------------------------
# Agent Tools
# ---------------------------------------------------------------------------


@tool
def review_stack(
    template: str,
    format: str = "cloudformation",
    focus_pillars: list[str] | None = None,
    context: str | None = None,
) -> str:
    """Analyze a CloudFormation template against Well-Architected best practices.

    Args:
        template: CloudFormation template content (YAML or JSON)
        format: Must be 'cloudformation'
        focus_pillars: Optional list of WA pillars to focus on
        context: Optional workload context description

    Returns:
        JSON string with review findings and summary
    """
    trace = start_review_trace()
    try:
        with trace_stage("parse") as span:
            graph = parse_template(template, format)
            span.attributes["resource_count"] = len(graph.nodes)

        with trace_stage("static_analysis") as span:
            static_findings, passed_checks = run_static_analysis(
                graph, _built_in_rules, focus_pillars
            )
            span.attributes["findings_count"] = len(static_findings)

        semantic_unavailable = False
        with trace_stage("semantic_analysis") as span:
            semantic_findings, semantic_unavailable = run_semantic_analysis(
                graph, context=context, org_rules=_org_rules or None
            )
            span.attributes["findings_count"] = len(semantic_findings)

        with trace_stage("generate_fixes"):
            all_findings = static_findings + semantic_findings
            fixes = generate_fixes(
                all_findings, graph, graph.template_format, rules=_built_in_rules
            )

        with trace_stage("compose_response"):
            response = compose_response(
                static_findings=static_findings,
                semantic_findings=semantic_findings,
                fixes=fixes,
                graph=graph,
                passed_checks=passed_checks,
                semantic_unavailable=semantic_unavailable,
            )

        trace.set_review_status("success")
        result = {
            "summary": {
                "total_resources": response.summary.total_resources,
                "total_findings": response.summary.total_findings,
                "critical": response.summary.critical,
                "warning": response.summary.warning,
                "info": response.summary.info,
                "passed_checks": response.summary.passed_checks,
            },
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity,
                    "pillar": f.pillar,
                    "resource": f.resource,
                    "title": f.title,
                    "description": f.description,
                    "fix": {"description": f.fix.description, "code": f.fix.code},
                }
                for f in response.findings
            ],
        }

        # Enrich critical/warning findings with AWS documentation references
        with trace_stage("docs_enrichment"):
            result["findings"] = enrich_findings_with_docs(result["findings"])

        return json.dumps(result, indent=2)

    except (ParseError, EmptyTemplateError, InvalidFormatError,
            InvalidPillarError, ResourceLimitError) as exc:
        trace.set_review_status("error")
        return json.dumps({"error": {"code": type(exc).__name__, "message": str(exc)}})
    except Exception as exc:
        trace.set_review_status("error")
        return json.dumps({"error": {"code": "InternalError", "message": str(exc)}})
    finally:
        # Emit the per-stage trace as structured JSON so it is queryable in
        # CloudWatch Logs Insights, complementing AgentCore's native OTEL traces.
        try:
            logger.info("REVIEW_TRACE %s", json.dumps(trace_to_dict(trace)))
        except Exception:  # never let observability logging break a review
            pass
        clear_current_trace()


@tool
def lookup_aws_docs(query: str, limit: int = 3) -> str:
    """Search AWS documentation for best-practice guidance.

    Use this tool to find authoritative AWS documentation related to
    architecture decisions, security best practices, or service configuration.
    The search is performed via the AgentCore Gateway MCP server.

    Args:
        query: Search phrase (e.g., "S3 bucket encryption best practices")
        limit: Maximum number of results (1-5)

    Returns:
        JSON with matching documentation pages including URLs and snippets
    """
    limit = max(1, min(5, limit))
    docs = search_aws_docs(query, limit=limit)
    if not docs:
        return json.dumps({
            "results": [],
            "message": "No documentation found or Gateway unavailable",
        })
    return json.dumps({"results": docs, "count": len(docs)})


@tool
def remediate_finding(resource_id: str, action: str = "enable_encryption") -> str:
    """Attempt to auto-remediate a finding by modifying live infrastructure.

    This calls the `modify_infrastructure` tool through the AgentCore Gateway.
    That tool is deliberately governed by an AgentCore Policy (Cedar) in
    ENFORCE mode: write access to live infrastructure is forbidden, so the
    Gateway blocks the call before it ever reaches the underlying Lambda.

    Use this when a user asks the agent to automatically fix, remediate, or
    apply a change to a resource it just reviewed. The agent does not have
    standing permission to mutate infrastructure; this tool demonstrates that
    the platform — not the agent — enforces that boundary.

    Args:
        resource_id: The logical ID or ARN of the resource to modify.
        action: The modification to attempt (e.g. "enable_encryption",
            "block_public_access").

    Returns:
        JSON describing the outcome. On a policy block, status is "denied"
        with the Gateway's policy-enforcement error. No infrastructure is
        modified in any case.
    """
    outcome = call_gateway_tool(
        "infra-modifier___modify_infrastructure",
        {"resource_id": resource_id, "action": action},
    )

    if outcome.get("status") == "denied":
        return json.dumps({
            "status": "blocked_by_policy",
            "resource_id": resource_id,
            "action": action,
            "detail": outcome.get("error", {}),
            "explanation": (
                "AgentCore Gateway denied this tool call via an enforced Cedar "
                "policy. The agent cannot modify live infrastructure; remediation "
                "must be applied through a governed change process."
            ),
        })

    if outcome.get("status") == "unavailable":
        return json.dumps({
            "status": "unavailable",
            "message": outcome.get("message", "Gateway unavailable"),
        })

    # status == "allowed": the policy did NOT block the call. The underlying
    # Lambda is a no-op stub, so nothing was actually changed — surface that.
    return json.dumps({
        "status": "not_blocked",
        "resource_id": resource_id,
        "action": action,
        "result": outcome.get("result", {}),
        "warning": (
            "The infrastructure-modification tool was NOT blocked by policy. "
            "Verify the DenyInfraModify Cedar policy is attached in ENFORCE mode."
        ),
    })


# ---------------------------------------------------------------------------
# Agent and App setup
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are the Architecture Review Agent. You review CloudFormation templates \
against AWS Well-Architected best practices.

When a user provides a CloudFormation template, use the review_stack tool to \
analyze it.

You have access to AWS documentation via the lookup_aws_docs tool. Use it to \
back your recommendations with authoritative guidance when users ask for more \
detail about a finding or best practice.

If a user asks you to automatically fix, remediate, or apply a change to a \
reviewed resource, use the remediate_finding tool. Note that modifying live \
infrastructure is governed by an enforced AgentCore policy: when the platform \
blocks the action, report that the change was denied by policy and recommend \
applying the fix through a governed change process instead.

Always provide clear, actionable findings with severity levels and specific \
fix recommendations. Format your response in a readable way for developers.
"""

app = BedrockAgentCoreApp()

MODEL_ID = "us.anthropic.claude-sonnet-4-6"
AGENT_TOOLS = [
    review_stack,
    lookup_aws_docs,
    remediate_finding,
]


def build_agent() -> Agent:
    """Construct a fresh Strands Agent.

    A new instance is created per invocation rather than shared as a module
    global. Strands `Agent` is stateful and not reentrant: AgentCore may route
    concurrent invocations to the same warm microVM, and a shared instance
    raises ConcurrencyException ("Agent is already processing a request"). A
    per-invocation agent keeps each request isolated.
    """
    return Agent(
        model=MODEL_ID,
        system_prompt=SYSTEM_PROMPT,
        tools=AGENT_TOOLS,
    )


# ---------------------------------------------------------------------------
# Asynchronous "deep review" — the laptop-problem demo
# ---------------------------------------------------------------------------
#
# A long review runs server-side as a background task. The caller fires it and
# disconnects (closes the laptop); the agent keeps working in its microVM and
# reconnects later to collect the finished result from S3.
#
# Results are persisted to S3 (bucket: archreview-results-{account}-{region})
# so they survive microVM termination and can be retrieved long after (up to
# the bucket's 30-day lifecycle expiration).
import re
import threading

_async_lock = threading.Lock()
# Track in-flight tasks locally (just for HealthyBusy lifecycle management)
_async_tasks: dict[str, int] = {}

# Optional delay (seconds) injected into the async job so a real "deep review of
# a large multi-stack estate" runs long enough to disconnect across. Demo knob.
REVIEW_EXTRA_DELAY_SECONDS = int(os.getenv("REVIEW_EXTRA_DELAY_SECONDS", "0"))

# Session key validation: only allow alphanumeric characters and hyphens (UUID-like)
_SESSION_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9\-]{1,128}$")


def _validate_session_key(session_key: str) -> bool:
    """Validate session_key format to prevent S3 key injection."""
    return bool(_SESSION_KEY_PATTERN.match(session_key))


def _extract_user_id(context: Any) -> str:
    """Extract user identity from the invocation context.

    Returns a user identifier from the JWT claims, or 'anonymous' if unavailable.
    """
    if context is None:
        return "anonymous"
    try:
        # AgentCore passes authentication context with JWT claims
        if isinstance(context, dict):
            # Try common JWT claim locations
            sub = context.get("sub") or context.get("claims", {}).get("sub")
            if sub:
                return sub
            # Try cognito:username
            username = context.get("cognito:username") or context.get("claims", {}).get("cognito:username")
            if username:
                return username
        return "anonymous"
    except Exception:
        return "anonymous"


def _get_user_scoped_s3_key(user_id: str, session_key: str) -> str:
    """Build a user-scoped S3 key to enforce tenant isolation."""
    return f"reviews/{user_id}/{session_key}.json"


def _get_results_bucket() -> str:
    """Get the S3 bucket name for storing review results."""
    import boto3
    # Derive bucket name from account and region (matches CDK stack)
    sts = boto3.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = os.getenv("AWS_REGION", "us-east-1")
    return f"archreview-results-{account}-{region}"


def _store_review_result(session_key: str, result: dict[str, Any], user_id: str = "anonymous") -> None:
    """Persist a review result to S3 for durable retrieval.

    Results are stored under a user-scoped prefix to enforce tenant isolation.
    """
    import boto3
    try:
        bucket = _get_results_bucket()
        s3 = boto3.client("s3", region_name=os.getenv("AWS_REGION", "us-east-1"))
        s3_key = _get_user_scoped_s3_key(user_id, session_key)
        content = json.dumps(result)
        s3.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=content.encode("utf-8"),
            ContentType="application/json",
        )
        logger.info(f"Stored review result in S3: s3://{bucket}/{s3_key} ({len(content)} bytes)")
    except Exception as exc:
        logger.error(f"Failed to persist review result to S3: {exc}")


def _retrieve_review_result(session_key: str, user_id: str = "anonymous") -> dict[str, Any] | None:
    """Retrieve a review result from S3.

    Only retrieves results owned by the specified user_id (tenant isolation).
    """
    import boto3
    try:
        bucket = _get_results_bucket()
        s3 = boto3.client("s3", region_name=os.getenv("AWS_REGION", "us-east-1"))
        s3_key = _get_user_scoped_s3_key(user_id, session_key)
        response = s3.get_object(
            Bucket=bucket,
            Key=s3_key,
        )
        content = response["Body"].read().decode("utf-8")
        return json.loads(content)
    except Exception as exc:
        # NoSuchKey means the review hasn't been stored yet (still processing)
        if "NoSuchKey" in str(exc):
            return None
        logger.warning(f"Failed to retrieve review result from S3: {exc}")
        return None


def _run_review_async(
    session_key: str,
    template: str,
    fmt: str,
    focus_pillars: list[str] | None,
    context_str: str | None,
    task_id: int,
    user_id: str = "anonymous",
) -> None:
    """Run the review pipeline in a background thread and persist the result to S3."""
    import time as _time
    try:
        if REVIEW_EXTRA_DELAY_SECONDS > 0:
            _time.sleep(REVIEW_EXTRA_DELAY_SECONDS)
        result_json = review_stack(template, fmt, focus_pillars, context_str)
        result = {
            "status": "complete",
            "result": json.loads(result_json),
            "completed_at": _time.time(),
        }
        _store_review_result(session_key, result, user_id=user_id)
    except Exception as exc:  # noqa: BLE001 — record any failure for the poller
        error_result = {"status": "error", "error": str(exc)}
        _store_review_result(session_key, error_result, user_id=user_id)
    finally:
        try:
            app.complete_async_task(task_id)
        except Exception:
            pass
        with _async_lock:
            _async_tasks.pop(session_key, None)


def _handle_async_action(payload: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Dispatch the async laptop-problem actions (start_review / get_result).

    Enforces ownership via user_id extracted from the authentication context.
    """
    action = payload.get("action")
    user_id = _extract_user_id(context)

    if action == "start_review":
        session_key = payload.get("session_key", "")
        template = payload.get("template", "")
        if not session_key or not template:
            return {"status": "error", "error": "session_key and template are required"}

        # Validate session_key format to prevent S3 key injection
        if not _validate_session_key(session_key):
            return {"status": "error", "error": "session_key must be 1-128 alphanumeric characters or hyphens"}

        # Mark the session busy so its microVM survives past the idle timeout
        # while the review runs (ping reports HealthyBusy).
        task_id = app.add_async_task("deep_review", {"session_key": session_key})
        with _async_lock:
            _async_tasks[session_key] = task_id

        threading.Thread(
            target=_run_review_async,
            args=(
                session_key,
                template,
                payload.get("format", "cloudformation"),
                payload.get("focus_pillars"),
                payload.get("context"),
                task_id,
                user_id,
            ),
            daemon=True,
        ).start()
        logger.info(f"Started async review for session_key={session_key} user={user_id} (task {task_id})")
        return {
            "status": "started",
            "session_key": session_key,
            "task_id": task_id,
            "message": (
                "Deep review started. The agent continues running server-side in "
                "its own microVM — you can disconnect. Reconnect with the same "
                "session and action=get_result to collect the findings."
            ),
        }

    if action == "get_result":
        session_key = payload.get("session_key", "")

        # Validate session_key format
        if not _validate_session_key(session_key):
            return {"status": "error", "error": "session_key must be 1-128 alphanumeric characters or hyphens"}

        # First check if still in-flight locally
        with _async_lock:
            if session_key in _async_tasks:
                return {"status": "processing", "session_key": session_key}

        # Retrieve from S3 — scoped to the caller's user_id (tenant isolation)
        result = _retrieve_review_result(session_key, user_id=user_id)
        if result is None:
            return {"status": "not_found", "session_key": session_key}
        return {"session_key": session_key, **result}

    return {"status": "error", "error": f"Unknown action: {action}"}


@app.entrypoint
def invoke(payload: dict[str, Any], context: Any) -> Any:
    """Main entry point invoked by AgentCore Runtime.

    Two modes:
    - Async (laptop problem): payload has an "action" (start_review/get_result).
    - Synchronous: payload has a "prompt" — the agent handles it directly.
    """
    if payload.get("action"):
        return _handle_async_action(payload, context=context)

    prompt = payload.get("prompt", "")
    logger.info(f"Received prompt: {prompt[:100]}...")

    agent = build_agent()
    response = agent(prompt)
    try:
        return response.message["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return str(response)


# Seed WA rules on startup
try:
    _seed_wa_rules_to_memory()
except Exception as exc:
    logger.warning(f"Rule seeding on startup failed (non-fatal): {exc}")

# Seed org rules on startup
try:
    _seed_org_rules_to_memory()
except Exception as exc:
    logger.warning(f"Org rule seeding on startup failed (non-fatal): {exc}")


if __name__ == "__main__":
    app.run()

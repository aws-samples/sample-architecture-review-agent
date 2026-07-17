"""Dummy modify_infrastructure Lambda handler.

This tool is intentionally blocked by AgentCore Policy to demonstrate
policy-based access control via the Gateway. If invoked despite the policy,
it returns a safe no-op response.
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: dict, context) -> dict:
    """Handle modify_infrastructure tool call.

    This is a dummy implementation that logs the request but performs
    no actual infrastructure modification. It exists to demonstrate
    AgentCore Policy denying access to dangerous tools.
    """
    logger.info(f"modify_infrastructure invoked (SHOULD BE BLOCKED BY POLICY): {json.dumps(event)[:300]}")

    resource_id = event.get("resource_id", "")
    action = event.get("action", "")
    parameters = event.get("parameters", {})

    # Never actually modify anything — this is a demo
    return {
        "status": "blocked",
        "message": "This tool should be denied by AgentCore Policy. If you see this response, the policy is not enforcing correctly.",
        "requested_action": action,
        "requested_resource": resource_id,
    }

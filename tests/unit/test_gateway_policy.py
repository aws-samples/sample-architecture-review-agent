"""Unit tests for the Gateway allow/deny path used in the Topic 2 demo.

These cover `call_gateway_tool` (which surfaces AgentCore Policy decisions) and
the `remediate_finding` agent tool that depends on it. The SigV4/transport layer
(`_gateway_jsonrpc_call`) is mocked, since signing and HTTP are exercised live
against a deployed Gateway, not in unit tests.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from src.docs_lookup import call_gateway_tool


# ---------------------------------------------------------------------------
# call_gateway_tool — allow / deny / unavailable
# ---------------------------------------------------------------------------


class TestCallGatewayTool:
    """Tests for the structured allow/deny Gateway invocation."""

    def test_denied_when_policy_forbids(self):
        """A JSON-RPC error (policy block) maps to status 'denied'."""
        rpc_error = {
            "code": -32002,
            "message": "Tool Execution Denied: Tool call not allowed due to policy enforcement",
        }
        with patch(
            "src.docs_lookup._gateway_jsonrpc_call",
            return_value={"jsonrpc": "2.0", "id": 1, "error": rpc_error},
        ):
            outcome = call_gateway_tool(
                "infra-modifier___modify_infrastructure",
                {"resource_id": "MyBucket", "action": "enable_encryption"},
            )
        assert outcome["status"] == "denied"
        assert outcome["error"]["code"] == -32002

    def test_allowed_unwraps_text_content_as_json(self):
        """A successful MCP result with a JSON text block is unwrapped."""
        payload = {"search_results": [{"url": "https://docs.aws.amazon.com/x"}]}
        rpc_ok = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": json.dumps(payload)}]},
        }
        with patch("src.docs_lookup._gateway_jsonrpc_call", return_value=rpc_ok):
            outcome = call_gateway_tool("aws-docs___search_documentation", {"search_phrase": "s3"})
        assert outcome["status"] == "allowed"
        assert outcome["result"] == payload

    def test_allowed_with_non_json_text_content(self):
        """A successful result whose text is not JSON is returned as content."""
        rpc_ok = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "plain text"}]},
        }
        with patch("src.docs_lookup._gateway_jsonrpc_call", return_value=rpc_ok):
            outcome = call_gateway_tool("aws-docs___read_documentation", {"url": "u"})
        assert outcome["status"] == "allowed"
        assert outcome["result"] == {"content": "plain text"}

    def test_unavailable_when_no_response(self):
        """A transport failure (None) maps to status 'unavailable'."""
        with patch("src.docs_lookup._gateway_jsonrpc_call", return_value=None):
            outcome = call_gateway_tool("infra-modifier___modify_infrastructure", {})
        assert outcome["status"] == "unavailable"


# ---------------------------------------------------------------------------
# remediate_finding agent tool — demo behavior
# ---------------------------------------------------------------------------


class TestRemediateFinding:
    """Tests for the remediate_finding tool (the gateway DENY trigger)."""

    def test_reports_blocked_by_policy_on_deny(self):
        from src.main import remediate_finding

        deny = {
            "status": "denied",
            "error": {"code": -32002, "message": "Tool Execution Denied"},
        }
        with patch("src.main.call_gateway_tool", return_value=deny):
            result = json.loads(remediate_finding("MyBucket", "enable_encryption"))
        assert result["status"] == "blocked_by_policy"
        assert result["resource_id"] == "MyBucket"
        assert result["detail"]["code"] == -32002

    def test_warns_when_not_blocked(self):
        from src.main import remediate_finding

        allowed = {"status": "allowed", "result": {"status": "blocked"}}
        with patch("src.main.call_gateway_tool", return_value=allowed):
            result = json.loads(remediate_finding("MyBucket", "enable_encryption"))
        assert result["status"] == "not_blocked"
        assert "warning" in result

    def test_reports_unavailable(self):
        from src.main import remediate_finding

        with patch(
            "src.main.call_gateway_tool",
            return_value={"status": "unavailable", "message": "no gateway"},
        ):
            result = json.loads(remediate_finding("MyBucket"))
        assert result["status"] == "unavailable"

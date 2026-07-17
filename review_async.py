#!/usr/bin/env python3
"""Laptop-problem demo client for the Architecture Review Agent.

Demonstrates AgentCore Runtime session persistence: a long "deep review" runs
server-side in the agent's microVM. The developer fires it and disconnects
(closes the laptop); the agent keeps working. Reconnecting later with the SAME
runtime session retrieves the completed result — the job never depended on the
laptop staying open.

Two subcommands:

    # 1. Fire the review, then "close the laptop" (process exits)
    python review_async.py start <template-file>
        → prints a SESSION ID to reconnect with

    # 2. Reconnect (fresh auth, same session) and collect the result
    python review_async.py result <session-id>

Or run the whole thing end-to-end with a simulated disconnect:

    python review_async.py demo <template-file>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

import boto3
import requests

REGION = "us-east-1"
STACK_NAME = "AgentCore-archreviewagent-default"
_HTTP_TIMEOUT = 60


def _load_env_file():
    """Load variables from .env file if it exists (no external dependency)."""
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                if key.strip() not in os.environ:
                    os.environ[key.strip()] = value.strip()


_load_env_file()

# Same Cognito identity as review.py (JWT inbound auth).
# Loaded from .env (written by deploy.py) or from environment variables.
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_USERNAME = os.environ.get("COGNITO_USERNAME", "")
COGNITO_PASSWORD = os.environ.get("COGNITO_PASSWORD", "")


def get_bearer_token() -> str:
    missing = [
        name for name, val in (
            ("COGNITO_CLIENT_ID", COGNITO_CLIENT_ID),
            ("COGNITO_USERNAME", COGNITO_USERNAME),
            ("COGNITO_PASSWORD", COGNITO_PASSWORD),
        ) if not val
    ]
    if missing:
        print(
            "Error: missing required environment variables: " + ", ".join(missing) +
            "\n  Run setup_cognito.py, then export COGNITO_CLIENT_ID / COGNITO_USERNAME / "
            "COGNITO_PASSWORD before invoking.",
            file=sys.stderr,
        )
        sys.exit(1)
    idp = boto3.client("cognito-idp", region_name=REGION)
    resp = idp.initiate_auth(
        ClientId=COGNITO_CLIENT_ID,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": COGNITO_USERNAME, "PASSWORD": COGNITO_PASSWORD},
    )
    return resp["AuthenticationResult"]["AccessToken"]


def get_runtime_arn() -> str:
    cfn = boto3.client("cloudformation", region_name=REGION)
    outputs = cfn.describe_stacks(StackName=STACK_NAME)["Stacks"][0]["Outputs"]
    for o in outputs:
        if "RuntimeArn" in o["OutputKey"]:
            return o["OutputValue"]
    print("Error: RuntimeArn not found in stack outputs", file=sys.stderr)
    sys.exit(1)


def invoke(runtime_arn: str, payload: dict, session_id: str, token: str) -> dict:
    """POST to the JWT-protected runtime with a fresh bearer token."""
    escaped = urllib.parse.quote(runtime_arn, safe="")
    url = (
        f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/"
        f"{escaped}/invocations?qualifier=DEFAULT"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
    }
    resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=_HTTP_TIMEOUT)
    if resp.status_code >= 400:
        print(f"Error HTTP {resp.status_code}: {resp.text[:300]}", file=sys.stderr)
        sys.exit(1)
    body = resp.text
    if body.startswith('"') and body.endswith('"'):
        body = json.loads(body)
    return json.loads(body) if isinstance(body, str) else body


def _session_id_for(key: str) -> str:
    # Runtime session IDs must be 33+ chars; derive a stable one from the key.
    return f"laptop-demo-{key}".ljust(33, "0")


def start_review(template_path: str) -> str:
    """Fire the async review and return the session key to reconnect with."""
    template = Path(template_path).read_text()
    key = uuid.uuid4().hex
    session_id = _session_id_for(key)
    runtime_arn = get_runtime_arn()

    print(f"📄 Template: {template_path} ({len(template)} chars)")
    token = get_bearer_token()
    print(f"🔑 Authenticated as '{COGNITO_USERNAME}'")
    resp = invoke(
        runtime_arn,
        {"action": "start_review", "session_key": key, "template": template},
        session_id,
        token,
    )
    print(f"🚀 {resp.get('message', resp)}")
    print(f"\n🔑 SESSION KEY: {key}")
    print("   (the agent is now working server-side — you can close the laptop)")
    return key


def get_result(key: str, quiet: bool = False) -> dict:
    """Reconnect with a fresh token on the same session and fetch the result."""
    session_id = _session_id_for(key)
    runtime_arn = get_runtime_arn()
    token = get_bearer_token()  # fresh login — simulates a new laptop session
    if not quiet:
        print(f"🔑 Re-authenticated as '{COGNITO_USERNAME}' (new session, same agent)")
    return invoke(
        runtime_arn,
        {"action": "get_result", "session_key": key},
        session_id,
        token,
    )


def print_summary(result: dict) -> None:
    data = result.get("result", {})
    summary = data.get("summary", {})
    findings = data.get("findings", [])

    if summary:
        print("\n" + "=" * 60)
        print("DEEP REVIEW RESULT (retrieved after reconnect)")
        print("=" * 60)
        print(f"Resources analyzed: {summary.get('total_resources', 'N/A')}")
        print(f"Total findings:     {summary.get('total_findings', 0)}")
        print(f"  Critical: {summary.get('critical', 0)}  "
              f"Warning: {summary.get('warning', 0)}  Info: {summary.get('info', 0)}")
        print(f"  Passed checks: {summary.get('passed_checks', 0)}")
        print("-" * 60)

        # Print all findings grouped by severity
        severity_order = ["critical", "warning", "info"]
        severity_icons = {"critical": "🔴", "warning": "🟡", "info": "🔵"}

        for severity in severity_order:
            sev_findings = [f for f in findings if f.get("severity") == severity]
            if not sev_findings:
                continue
            print(f"\n{severity_icons.get(severity, '⚪')} {severity.upper()} ({len(sev_findings)})\n")
            for f in sev_findings:
                print(f"  [{f.get('id', '')}] {f.get('title', '')}")
                print(f"      Resource: {f.get('resource', '')}")
                print(f"      Pillar:   {f.get('pillar', '')}")
                print(f"      {f.get('description', '')}")
                fix = f.get("fix", {})
                if fix.get("description"):
                    print(f"      Fix: {fix['description']}")
                if fix.get("code"):
                    print(f"      Code:")
                    for line in fix["code"].splitlines():
                        print(f"        {line}")
                doc = f.get("doc_reference")
                if doc:
                    print(f"      📖 {doc.get('title', '')}: {doc.get('url', '')}")
                print()

        print("=" * 60)
    elif "error" in result:
        print(f"\n❌ Error: {result.get('error')}")
    else:
        print(json.dumps(result, indent=2))


def cmd_demo(template_path: str) -> None:
    """End-to-end: start → simulate disconnect → reconnect and poll."""
    key = start_review(template_path)
    print("\n💻 ...laptop closed. Walking away. (simulating disconnect)\n")
    time.sleep(10)
    print("💻 ...reopened the laptop. Reconnecting to the running session...\n")

    # Poll get_result until complete (fresh auth each time)
    deadline = time.time() + 180
    while time.time() < deadline:
        result = get_result(key, quiet=True)
        status = result.get("status")
        if status == "complete":
            print("✅ The review finished while we were away — collecting it now.")
            print_summary(result)
            return
        if status == "error":
            print(f"❌ Review errored server-side: {result.get('error')}", file=sys.stderr)
            return
        print(f"   status={status}, still running server-side... (reconnecting in 15s)")
        time.sleep(15)
    print("⚠️  Timed out waiting for the review to complete.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Laptop-problem async review demo")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_start = sub.add_parser("start", help="Fire the review, then disconnect")
    p_start.add_argument("template")

    p_result = sub.add_parser("result", help="Reconnect and fetch the result")
    p_result.add_argument("session_key")

    p_demo = sub.add_parser("demo", help="Full start → disconnect → reconnect flow")
    p_demo.add_argument("template")

    args = parser.parse_args()
    if args.cmd == "start":
        start_review(args.template)
    elif args.cmd == "result":
        print_summary(get_result(args.session_key))
    elif args.cmd == "demo":
        cmd_demo(args.template)


if __name__ == "__main__":
    main()

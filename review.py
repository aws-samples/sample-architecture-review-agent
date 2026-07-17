#!/usr/bin/env python3
"""CLI client for the Architecture Review Agent.

Invokes the agent on AgentCore Runtime asynchronously:
  1. Submits a CloudFormation template for review
  2. Polls for the response
  3. Prints the findings

Usage:
    python review.py <template-file>
    python review.py my-stack.yaml
    python review.py my-stack.yaml --pillars security,reliability
    python review.py my-stack.yaml --context "payment processing"
"""

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

# Configuration
REGION = "us-east-1"
RUNTIME_ARN = None  # Set via --runtime-arn or auto-detected from stack

# A full review runs Claude across the whole pipeline and can take 90-120s.
_HTTP_TIMEOUT = 300


def _load_env_file():
    """Load variables from .env file if it exists (no external dependency)."""
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                # Only set if not already in environment (explicit exports take precedence)
                if key.strip() not in os.environ:
                    os.environ[key.strip()] = value.strip()


_load_env_file()

# Cognito identity for AgentCore Runtime JWT (inbound) auth. The runtime accepts
# only bearer tokens issued by this user pool / app client (see setup_cognito.py
# and the CUSTOM_JWT authorizer in agentcore/agentcore.json). boto3 cannot pass
# bearer tokens, so invocation uses a signed-out HTTPS call with the token.
#
# Loaded from .env (written by deploy.py) or from environment variables:
#   export COGNITO_CLIENT_ID=...      # app client ID from setup_cognito.py
#   export COGNITO_USERNAME=...       # demo user
#   export COGNITO_PASSWORD=...       # demo user's password
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_USERNAME = os.environ.get("COGNITO_USERNAME", "")
COGNITO_PASSWORD = os.environ.get("COGNITO_PASSWORD", "")


def get_bearer_token() -> str:
    """Fetch a Cognito access token for the demo user (USER_PASSWORD_AUTH)."""
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
    """Get the runtime ARN from the CloudFormation stack outputs."""
    cfn = boto3.client("cloudformation", region_name=REGION)
    try:
        response = cfn.describe_stacks(StackName="AgentCore-archreviewagent-default")
        outputs = response["Stacks"][0]["Outputs"]
        for output in outputs:
            if "RuntimeArn" in output["OutputKey"]:
                return output["OutputValue"]
    except Exception as exc:
        print(f"Error: Could not find runtime ARN from stack: {exc}", file=sys.stderr)
        sys.exit(1)
    print("Error: RuntimeArn not found in stack outputs", file=sys.stderr)
    sys.exit(1)


def invoke_agent(runtime_arn: str, prompt: str, session_id: str, token: str) -> str:
    """Invoke the JWT-protected agent runtime with a bearer token.

    The runtime is configured for CUSTOM_JWT inbound auth, so invocation is a
    direct HTTPS POST carrying the Cognito access token (boto3 cannot pass
    bearer tokens). A missing or invalid token yields HTTP 401.

    Raises:
        PermissionError: on 401/403 (authentication/authorization failure).
        RuntimeError: on other non-2xx responses.
    """
    escaped_arn = urllib.parse.quote(runtime_arn, safe="")
    url = (
        f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/"
        f"{escaped_arn}/invocations?qualifier=DEFAULT"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
    }
    resp = requests.post(
        url, headers=headers, data=json.dumps({"prompt": prompt}), timeout=_HTTP_TIMEOUT
    )

    if resp.status_code in (401, 403):
        raise PermissionError(
            f"HTTP {resp.status_code} — token rejected by the runtime's JWT "
            f"authorizer. {resp.text[:200]}"
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")

    body = resp.text
    # The runtime returns a JSON-encoded string; unwrap one level if present.
    if body.startswith('"') and body.endswith('"'):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass
    return body


def print_findings(response_text: str):
    """Pretty-print the review findings."""
    # Try to extract JSON from the response
    try:
        # The agent response may contain markdown + JSON
        # Try to find JSON block
        if "```json" in response_text:
            start = response_text.index("```json") + 7
            end = response_text.index("```", start)
            data = json.loads(response_text[start:end])
        elif "{" in response_text:
            # Find the first JSON object
            start = response_text.index("{")
            # Find matching close
            data = json.loads(response_text[start:])
        else:
            # Just print the raw text
            print(response_text)
            return

        # Pretty print structured response
        if "summary" in data:
            s = data["summary"]
            print("\n" + "=" * 60)
            print("ARCHITECTURE REVIEW RESULTS")
            print("=" * 60)
            print(f"Resources analyzed: {s.get('total_resources', 'N/A')}")
            print(f"Total findings:     {s.get('total_findings', 0)}")
            print(f"  Critical:         {s.get('critical', 0)}")
            print(f"  Warning:          {s.get('warning', 0)}")
            print(f"  Info:             {s.get('info', 0)}")
            print(f"Passed checks:      {s.get('passed_checks', 0)}")
            print("-" * 60)

            for f in data.get("findings", []):
                severity_icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(
                    f.get("severity", ""), "⚪"
                )
                print(f"\n{severity_icon} [{f.get('id', '')}] {f.get('title', '')}")
                print(f"   Resource: {f.get('resource', '')}")
                print(f"   Pillar:   {f.get('pillar', '')}")
                print(f"   {f.get('description', '')}")
                fix = f.get("fix", {})
                if fix.get("code"):
                    print(f"   Fix: {fix.get('description', '')}")
            print("\n" + "=" * 60)
        elif "error" in data:
            print(f"\n❌ Error: {data['error'].get('message', str(data['error']))}")
        else:
            print(response_text)

    except (json.JSONDecodeError, ValueError):
        # Not JSON, print as-is (the agent gives a natural language response)
        print(response_text)


def main():
    parser = argparse.ArgumentParser(
        description="Review a CloudFormation template against Well-Architected best practices"
    )
    parser.add_argument("template", help="Path to CloudFormation template file (YAML or JSON)")
    parser.add_argument("--pillars", help="Comma-separated list of WA pillars to focus on")
    parser.add_argument("--context", help="Workload context (e.g., 'payment processing pipeline')")
    parser.add_argument("--runtime-arn", help="AgentCore Runtime ARN (auto-detected if not set)")
    parser.add_argument("--raw", action="store_true", help="Print raw response without formatting")
    # Identity / inbound-auth demo flags
    parser.add_argument("--no-auth", action="store_true",
                        help="Send no bearer token — expect HTTP 401 (auth denied)")
    parser.add_argument("--bad-token", action="store_true",
                        help="Send an invalid bearer token — expect HTTP 401 (auth denied)")
    # Policy denial demo
    parser.add_argument("--remediate",
                        help="Ask the agent to remediate a finding (triggers policy denial demo). "
                             "Value is the action to attempt, e.g. 'Enable encryption on MyBucket'")

    args = parser.parse_args()

    # Read template
    template_path = Path(args.template)
    if not template_path.exists():
        print(f"Error: File not found: {args.template}", file=sys.stderr)
        sys.exit(1)

    template_content = template_path.read_text()
    print(f"📄 Template: {args.template} ({len(template_content)} chars)")

    # Get runtime ARN
    runtime_arn = args.runtime_arn or get_runtime_arn()
    print(f"🔗 Runtime: {runtime_arn.split('/')[-1]}")

    # Build prompt
    if args.remediate:
        # Policy denial demo: ask the agent to remediate a finding on live infra
        prompt = (
            f"I just reviewed the template {args.template}. "
            f"Please remediate this finding by modifying the live infrastructure: "
            f"{args.remediate}"
        )
        print(f"🛡️  Policy demo: asking agent to remediate → '{args.remediate}'")
    else:
        prompt_parts = [f"Please review this CloudFormation template:\n\n{template_content}"]
        if args.pillars:
            prompt_parts.append(f"\nFocus on these pillars: {args.pillars}")
        if args.context:
            prompt_parts.append(f"\nWorkload context: {args.context}")
        prompt = "\n".join(prompt_parts)

    # Generate session ID for this review
    session_id = f"review-{uuid.uuid4().hex}-{int(time.time())}"

    # Obtain the bearer token for the runtime's JWT inbound auth (AgentCore
    # Identity). --no-auth / --bad-token simulate an unauthenticated caller.
    if args.no_auth:
        token = ""
        print("🔓 Auth: sending NO bearer token (expecting 401)")
    elif args.bad_token:
        token = "invalid.token.value"
        print("🔓 Auth: sending an INVALID bearer token (expecting 401)")
    else:
        token = get_bearer_token()
        print(f"🔑 Auth: authenticated as '{COGNITO_USERNAME}' (Cognito JWT)")

    # Invoke agent
    print(f"⏳ Submitting review (session: {session_id})...")
    start_time = time.time()

    try:
        response_text = invoke_agent(runtime_arn, prompt, session_id, token)
        elapsed = time.time() - start_time
        print(f"✅ Review completed in {elapsed:.1f}s")

        if args.raw:
            print(response_text)
        else:
            print_findings(response_text)

    except PermissionError as exc:
        elapsed = time.time() - start_time
        print(f"\n🚫 Access denied after {elapsed:.1f}s: {exc}", file=sys.stderr)
        print("   The runtime's AgentCore Identity (JWT) authorizer rejected the request.",
              file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        elapsed = time.time() - start_time
        print(f"\n❌ Review failed after {elapsed:.1f}s: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Automated deployment script for the Architecture Review Agent.

Handles the full two-phase deployment flow:
  1. Setup Cognito (if not already provisioned)
  2. Patch agentcore.json with Cognito values (policies temporarily removed)
  3. First deploy — creates gateway, runtime, memory (no Cedar policies yet)
  4. Retrieve the gateway ARN from CloudFormation stack outputs
  5. Patch agentcore.json with the real gateway ARN in Cedar policies
  6. Redeploy — adds the Cedar policies with the valid gateway ARN
  7. Restore agentcore.json to its placeholder state (safe for git)

The committed agentcore.json always keeps its placeholders — this script
patches it transiently during deploy and restores it afterward.

Usage:
    python deploy.py                    # Full deploy
    python deploy.py --region us-east-1 # Explicit region
    python deploy.py --skip-cognito     # Skip Cognito setup (already done)

Prerequisites:
    - AWS credentials configured (account matching aws-targets.json)
    - AgentCore CLI installed: npm install -g @aws/agentcore
    - CDK dependencies installed: cd archreviewagent/agentcore/cdk && npm install
    - Python venv with boto3 installed
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"
STACK_NAME = "AgentCore-archreviewagent-default"
PROJECT_ROOT = Path(__file__).parent
AGENTCORE_DIR = PROJECT_ROOT / "archreviewagent"
AGENTCORE_JSON = AGENTCORE_DIR / "agentcore" / "agentcore.json"

# Placeholders in the committed agentcore.json
COGNITO_POOL_PLACEHOLDER = "YOUR_COGNITO_POOL_ID"
COGNITO_CLIENT_PLACEHOLDER = "YOUR_COGNITO_CLIENT_ID"
ACCOUNT_PLACEHOLDER = "YOUR_ACCOUNT_ID"
GATEWAY_PLACEHOLDER = "YOUR_GATEWAY_ID"


def run_cmd(cmd: list[str], cwd: Path | None = None) -> bool:
    """Run a command with live output streaming. Returns True on success."""
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    return result.returncode == 0


def setup_cognito(region: str) -> dict:
    """Run setup_cognito.py and return the config dict."""
    print("\n[1/6] Setting up Cognito user pool...")
    sys.path.insert(0, str(PROJECT_ROOT))
    from setup_cognito import setup
    config = setup(region)
    print(f"  Pool ID:   {config['pool_id']}")
    print(f"  Client ID: {config['client_id']}")
    print(f"  Username:  {config['demo_username']}")
    return config


def get_existing_cognito(region: str) -> dict | None:
    """Check if the Cognito pool already exists and return config."""
    client = boto3.client("cognito-idp", region_name=region)
    paginator = client.get_paginator("list_user_pools")
    for page in paginator.paginate(MaxResults=60):
        for pool in page.get("UserPools", []):
            if pool["Name"] == "archreview-demo-pool":
                pool_id = pool["Id"]
                client_paginator = client.get_paginator("list_user_pool_clients")
                for cpage in client_paginator.paginate(UserPoolId=pool_id, MaxResults=60):
                    for c in cpage.get("UserPoolClients", []):
                        if c["ClientName"] == "archreview-demo-client":
                            return {
                                "pool_id": pool_id,
                                "client_id": c["ClientId"],
                                "discovery_url": f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration",
                                "demo_username": os.environ.get("COGNITO_USERNAME", "well-architected-agent"),
                                "demo_password": os.environ.get("COGNITO_PASSWORD", ""),
                                "region": region,
                            }
    return None


def read_agentcore_json() -> dict:
    """Read and parse agentcore.json."""
    return json.loads(AGENTCORE_JSON.read_text())


def write_agentcore_json(data: dict):
    """Write agentcore.json with consistent formatting."""
    AGENTCORE_JSON.write_text(json.dumps(data, indent=2) + "\n")


def patch_cognito(data: dict, cognito_config: dict) -> dict:
    """Patch Cognito values into agentcore.json data."""
    content = json.dumps(data)
    content = content.replace(COGNITO_POOL_PLACEHOLDER, cognito_config["pool_id"])
    content = content.replace(COGNITO_CLIENT_PLACEHOLDER, cognito_config["client_id"])
    return json.loads(content)


def patch_gateway_arn(data: dict, gateway_arn: str) -> dict:
    """Patch the real gateway ARN into Cedar policy statements."""
    account_id = gateway_arn.split(":")[4]
    gateway_id = gateway_arn.split("/")[-1]
    content = json.dumps(data)
    content = content.replace(ACCOUNT_PLACEHOLDER, account_id)
    content = content.replace(GATEWAY_PLACEHOLDER, gateway_id)
    return json.loads(content)


def remove_policies(data: dict) -> tuple[dict, list]:
    """Remove Cedar policies from the policy engine (keep the engine itself).
    
    The gateway's policyEngineConfiguration in mcp.json references the engine
    by name, so the engine must exist for CDK synth to succeed. Only the
    individual policies need the gateway ARN.
    """
    saved_policies = []
    data_copy = json.loads(json.dumps(data))  # deep copy
    for engine in data_copy.get("policyEngines", []):
        saved_policies = engine.get("policies", [])
        engine["policies"] = []
    return data_copy, saved_policies


def restore_policies(data: dict, policies: list) -> dict:
    """Restore Cedar policies to the policy engine."""
    data_copy = json.loads(json.dumps(data))  # deep copy
    for engine in data_copy.get("policyEngines", []):
        engine["policies"] = policies
    return data_copy


def get_gateway_arn(region: str) -> str | None:
    """Retrieve the gateway ARN from CloudFormation stack outputs."""
    cfn = boto3.client("cloudformation", region_name=region)
    try:
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = response["Stacks"][0].get("Outputs", [])
        for output in outputs:
            if "GatewayArnOutput" in output["OutputKey"]:
                return output["OutputValue"]
    except ClientError:
        pass
    return None


def stack_exists(region: str) -> bool:
    """Check if the CloudFormation stack exists and is not in a failed state."""
    cfn = boto3.client("cloudformation", region_name=region)
    try:
        response = cfn.describe_stacks(StackName=STACK_NAME)
        status = response["Stacks"][0]["StackStatus"]
        return status not in ("DELETE_COMPLETE", "DELETE_IN_PROGRESS")
    except ClientError as e:
        if "does not exist" in str(e):
            return False
        raise


def install_cdk_deps():
    """Ensure CDK node_modules are installed."""
    cdk_dir = AGENTCORE_DIR / "agentcore" / "cdk"
    if not (cdk_dir / "node_modules" / ".bin" / "tsc").exists():
        print("\n[*] Installing CDK dependencies...")
        run_cmd(["npm", "install"], cwd=cdk_dir)


def clean_orphaned_policies(region: str):
    """Delete orphaned policies from other policy engines that conflict by name."""
    print("  Checking for orphaned policies that may conflict...")
    client = boto3.client("bedrock-agentcore-control", region_name=region)
    target_names = {"AllowSearchDocs", "AllowReadDocs", "DenyInfraModify"}

    try:
        engines = client.list_policy_engines().get("policyEngines", [])
    except Exception:
        return

    for engine in engines:
        eid = engine["policyEngineId"]
        try:
            policies = client.list_policies(policyEngineId=eid).get("policies", [])
            for p in policies:
                if p["name"] in target_names:
                    print(f"  Deleting orphaned policy '{p['name']}' from engine '{eid}'...")
                    client.delete_policy(policyEngineId=eid, policyId=p["policyId"])
        except Exception:
            continue

    # Wait for deletions to propagate
    if target_names:
        print("  Waiting for policy deletions to propagate...")
        time.sleep(15)


def enable_observability(region: str):
    """Enable tracing and log delivery for Runtime and Gateway post-deploy.

    Uses the CloudWatch Logs vended delivery APIs to configure:
      - APPLICATION_LOGS delivery to a CloudWatch Log Group
      - TRACES delivery to X-Ray

    Idempotent: skips resources that already have delivery sources configured.
    """
    print("\n[*] Enabling observability (tracing + log delivery)...")
    logs_client = boto3.client("logs", region_name=region)
    cfn = boto3.client("cloudformation", region_name=region)
    sts = boto3.client("sts", region_name=region)
    account_id = sts.get_caller_identity()["Account"]

    # Get resource ARNs from stack outputs
    try:
        resp = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    except ClientError:
        print("  ⚠️  Could not read stack outputs, skipping observability setup.")
        return

    runtime_arn = None
    runtime_id = None
    gateway_arn = None
    gateway_id = None
    for key, val in outputs.items():
        if "RuntimeArn" in key:
            runtime_arn = val
        elif "RuntimeId" in key:
            runtime_id = val
        elif "GatewayArn" in key:
            gateway_arn = val
        elif "GatewayId" in key and "gateway" in key.lower():
            gateway_id = val

    # Extract IDs from ARNs if not found in outputs
    if runtime_arn and not runtime_id:
        runtime_id = runtime_arn.split("/")[-1]
    if gateway_arn and not gateway_id:
        gateway_id = gateway_arn.split("/")[-1]

    resources = []
    if runtime_arn:
        resources.append(("runtime", runtime_arn, runtime_id))
    if gateway_arn:
        resources.append(("gateway", gateway_arn, gateway_id))

    if not resources:
        print("  ⚠️  No Runtime or Gateway ARN found in outputs, skipping.")
        return

    for resource_type, resource_arn, resource_id in resources:
        # Use a shortened prefix to stay within the 60-char name limit for
        # delivery sources and destinations.
        if resource_type == "runtime":
            short_id = resource_id.split("-")[-1]  # last segment (e.g., "glMAij5vNw")
            prefix = f"archreview-rt-{short_id}"
        else:
            short_id = resource_id.split("-")[-1]  # last segment (e.g., "grzib5zxhv")
            prefix = f"archreview-gw-{short_id}"

        # --- APPLICATION_LOGS ---
        logs_source_name = f"{prefix}-logs-source"
        logs_dest_name = f"{prefix}-logs-dest"
        log_group_name = f"/aws/vendedlogs/bedrock-agentcore/{resource_id}"

        try:
            try:
                logs_client.get_delivery_source(name=logs_source_name)
                print(f"  ✓ {resource_type} logs delivery already configured, skipping.")
            except logs_client.exceptions.ResourceNotFoundException:
                # Create log group
                try:
                    logs_client.create_log_group(logGroupName=log_group_name)
                except logs_client.exceptions.ResourceAlreadyExistsException:
                    pass

                log_group_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}"

                # Create delivery source for logs
                logs_client.put_delivery_source(
                    name=logs_source_name,
                    logType="APPLICATION_LOGS",
                    resourceArn=resource_arn,
                )

                # Create delivery destination (CloudWatch Logs)
                dest_resp = logs_client.put_delivery_destination(
                    name=logs_dest_name,
                    deliveryDestinationType="CWL",
                    deliveryDestinationConfiguration={
                        "destinationResourceArn": log_group_arn,
                    },
                )

                # Create delivery (connect source to destination)
                logs_client.create_delivery(
                    deliverySourceName=logs_source_name,
                    deliveryDestinationArn=dest_resp["deliveryDestination"]["arn"],
                )
                print(f"  ✅ {resource_type} log delivery enabled → {log_group_name}")

        except Exception as exc:
            print(f"  ⚠️  Failed to enable {resource_type} log delivery: {exc}")

        # --- TRACES ---
        traces_source_name = f"{prefix}-traces-source"
        traces_dest_name = f"{prefix}-traces-dest"

        try:
            try:
                logs_client.get_delivery_source(name=traces_source_name)
                print(f"  ✓ {resource_type} tracing already configured, skipping.")
            except logs_client.exceptions.ResourceNotFoundException:
                # Create traces delivery source
                logs_client.put_delivery_source(
                    name=traces_source_name,
                    logType="TRACES",
                    resourceArn=resource_arn,
                )

                # Create traces delivery destination (X-Ray)
                traces_dest_resp = logs_client.put_delivery_destination(
                    name=traces_dest_name,
                    deliveryDestinationType="XRAY",
                )

                # Create delivery (connect source to destination)
                logs_client.create_delivery(
                    deliverySourceName=traces_source_name,
                    deliveryDestinationArn=traces_dest_resp["deliveryDestination"]["arn"],
                )
                print(f"  ✅ {resource_type} tracing enabled → X-Ray")

        except Exception as exc:
            print(f"  ⚠️  Failed to enable {resource_type} tracing: {exc}")


def show_status(region: str):
    """Show deployment status from CloudFormation stack outputs."""
    print("=" * 60)
    print("  Architecture Review Agent - Deployment Status")
    print("=" * 60)
    print(f"\n  Region: {region}")

    cfn = boto3.client("cloudformation", region_name=region)
    try:
        resp = cfn.describe_stacks(StackName=STACK_NAME)
        stack = resp["Stacks"][0]
        print(f"  Stack:  {STACK_NAME} ({stack['StackStatus']})")
        print()

        outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

        # Runtime
        for key, val in outputs.items():
            if "RuntimeArn" in key:
                print(f"  Agent Runtime:     {val}")
                break

        # Gateway
        for key, val in outputs.items():
            if "GatewayArn" in key:
                print(f"  Gateway ARN:       {val}")
                break
        for key, val in outputs.items():
            if "GatewayUrl" in key:
                print(f"  Gateway URL:       {val}")
                break

        # Memory
        for key, val in outputs.items():
            if "MemoryArn" in key:
                print(f"  Memory ARN:        {val}")
                break

        # Policy Engine
        for key, val in outputs.items():
            if "PolicyEngineArn" in key:
                print(f"  Policy Engine ARN: {val}")
                break

        # Cognito
        cognito_config = get_existing_cognito(region)
        if cognito_config:
            print(f"  Cognito Pool:      {cognito_config['pool_id']}")
            print(f"  Cognito Client:    {cognito_config['client_id']}")
        else:
            print(f"  Cognito Pool:      not found")

        print()
    except ClientError as e:
        if "does not exist" in str(e):
            print(f"\n  Stack '{STACK_NAME}' not found — not deployed.\n")
        else:
            print(f"\n  Error: {e}\n")


def main():
    parser = argparse.ArgumentParser(description="Deploy the Architecture Review Agent")
    parser.add_argument("--region", default=REGION, help="AWS region (default: us-east-1)")
    parser.add_argument("--skip-cognito", action="store_true",
                        help="Skip Cognito setup (use existing pool)")
    parser.add_argument("--status", action="store_true",
                        help="Show deployment status and exit (no deploy)")
    args = parser.parse_args()

    if args.status:
        show_status(args.region)
        return

    print("=" * 60)
    print("  Architecture Review Agent - Automated Deploy")
    print("=" * 60)

    # Verify AWS credentials
    sts = boto3.client("sts", region_name=args.region)
    identity = sts.get_caller_identity()
    print(f"\n  Account: {identity['Account']}")
    print(f"  Region:  {args.region}")

    # Step 0: Install CDK dependencies if needed
    install_cdk_deps()

    # Step 1: Setup or find Cognito
    if args.skip_cognito:
        cognito_config = get_existing_cognito(args.region)
        if not cognito_config:
            print("Error: --skip-cognito specified but no existing pool found.", file=sys.stderr)
            sys.exit(1)
        print(f"\n[1/6] Using existing Cognito pool: {cognito_config['pool_id']}")
    else:
        cognito_config = setup_cognito(args.region)

    # Save original file content for restoration
    original_content = AGENTCORE_JSON.read_text()

    try:
        # Step 2: Check if gateway already exists (update path vs fresh deploy)
        gateway_arn = get_gateway_arn(args.region) if stack_exists(args.region) else None

        if gateway_arn:
            # UPDATE PATH: Gateway exists — deploy with everything in one shot
            print(f"\n[2/6] Found existing gateway: {gateway_arn}")
            print("\n[3/6] Patching agentcore.json with all deployment values...")

            data = read_agentcore_json()
            data = patch_cognito(data, cognito_config)
            data = patch_gateway_arn(data, gateway_arn)
            write_agentcore_json(data)

            print("\n[4/6] Deploying to AWS...")
            success = run_cmd(["agentcore", "deploy", "-y"], cwd=AGENTCORE_DIR)

            if not success:
                # May need to clean orphaned policies
                clean_orphaned_policies(args.region)
                print("\n[5/6] Retrying deploy after cleanup...")
                success = run_cmd(["agentcore", "deploy", "-y"], cwd=AGENTCORE_DIR)
            else:
                print("\n[5/6] Deploy succeeded on first attempt")

        else:
            # FRESH DEPLOY PATH: No gateway yet — two-phase deploy
            print("\n[2/6] No existing gateway — performing two-phase deploy")

            # Phase 1: Deploy WITHOUT policies (so gateway gets created)
            print("\n[3/6] Patching agentcore.json (without Cedar policies for phase 1)...")
            data = read_agentcore_json()
            data = patch_cognito(data, cognito_config)
            data_no_policies, saved_policies = remove_policies(data)
            write_agentcore_json(data_no_policies)

            print("\n[4/6] Phase 1: Deploying infrastructure (runtime, gateway, memory)...")
            success = run_cmd(["agentcore", "deploy", "-y"], cwd=AGENTCORE_DIR)

            if not success:
                print("\n  ERROR: Phase 1 deploy failed.", file=sys.stderr)
                sys.exit(1)

            # Get the gateway ARN from the newly created stack
            gateway_arn = get_gateway_arn(args.region)
            if not gateway_arn:
                print("\n  ERROR: Gateway was not created. Check stack outputs.", file=sys.stderr)
                sys.exit(1)
            print(f"\n  Gateway created: {gateway_arn}")

            # Clean any orphaned policies before phase 2
            clean_orphaned_policies(args.region)

            # Phase 2: Redeploy WITH policies (now that we have the gateway ARN)
            print("\n[5/6] Phase 2: Adding Cedar policies with gateway ARN...")
            data = read_agentcore_json()  # re-read (may have been updated by CLI)
            # It won't have policies since we removed them, so restore
            data = restore_policies(data, saved_policies)
            data = patch_cognito(data, cognito_config)
            data = patch_gateway_arn(data, gateway_arn)
            write_agentcore_json(data)

            success = run_cmd(["agentcore", "deploy", "-y"], cwd=AGENTCORE_DIR)

        if not success:
            print("\n  ERROR: Deploy failed.", file=sys.stderr)
            sys.exit(1)

    finally:
        # Step 6: Always restore agentcore.json to its original placeholder state
        print("\n[6/6] Restoring agentcore.json to placeholder state (safe for git)...")
        AGENTCORE_JSON.write_text(original_content)

    # Enable observability (tracing + log delivery) for Runtime and Gateway
    enable_observability(args.region)

    # Write .env file for review.py / review_async.py with restricted permissions
    env_file = PROJECT_ROOT / ".env"
    env_lines = [
        f"COGNITO_CLIENT_ID={cognito_config['client_id']}",
        f"COGNITO_USERNAME={cognito_config['demo_username']}",
    ]
    # Include password if available (from setup or environment)
    password = cognito_config.get("demo_password", "")
    if not password and env_file.exists():
        # Preserve existing password from .env if we don't have a new one
        for line in env_file.read_text().splitlines():
            if line.startswith("COGNITO_PASSWORD="):
                password = line.split("=", 1)[1]
                break
    if password:
        env_lines.append(f"COGNITO_PASSWORD={password}")

    # Write with restricted file permissions (owner read/write only)
    env_file.write_text("\n".join(env_lines) + "\n")
    os.chmod(env_file, 0o600)

    # Fetch deployment info from stack outputs for display
    runtime_arn = None
    gateway_url = None
    try:
        cfn = boto3.client("cloudformation", region_name=args.region)
        resp = cfn.describe_stacks(StackName=STACK_NAME)
        for output in resp["Stacks"][0].get("Outputs", []):
            if "RuntimeArn" in output["OutputKey"]:
                runtime_arn = output["OutputValue"]
            elif "GatewayUrl" in output["OutputKey"]:
                gateway_url = output["OutputValue"]
    except Exception:
        pass

    # Print success
    print("\n" + "=" * 60)
    print("  ✅ Deployment complete!")
    print("=" * 60)
    print(f"\n  Credentials written to: .env")
    print("  (review.py loads this automatically — no manual export needed)")
    print(f"\n  Deployed Resources:")
    if runtime_arn:
        print(f"    Runtime ARN:  {runtime_arn}")
    if gateway_arn:
        print(f"    Gateway ARN:  {gateway_arn}")
    if gateway_url:
        print(f"    Gateway URL:  {gateway_url}")
    print(f"\n  Test with: python review.py test-stack.yaml\n")


if __name__ == "__main__":
    main()

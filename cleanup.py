#!/usr/bin/env python3
"""Cleanup script for the Architecture Review Agent.

Removes all deployed resources in the correct order:
1. Observability deliveries (log + trace delivery sources, destinations, deliveries)
2. CloudWatch Log Groups (orphaned by the Lambda functions after stack deletion)
3. CloudFormation stack — Runtime, Memory, Gateway, Lambdas, the Policy Engine
   and its Cedar policies, and IAM roles
4. Cognito User Pool (created by setup_cognito.py, outside the CFN stack)

Ordering matters: the Cognito pool is deleted LAST, after the CloudFormation
stack. The runtime's JWT authorizer references the pool's OpenID discovery URL,
so CloudFormation must be able to reach that URL while it tears the runtime
down. Deleting the pool first makes the runtime delete fail with
"Failed to fetch discovery document ..." and leaves the stack in DELETE_FAILED.

The Policy Engine and policies are part of the CloudFormation stack (declared in
agentcore.json), so deleting the stack removes them; no separate teardown step
is needed.

Usage:
    python cleanup.py              # Interactive (asks for confirmation)
    python cleanup.py --force      # Skip confirmation prompts
    python cleanup.py --region us-west-2  # Use a different region
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

STACK_NAME = "AgentCore-archreviewagent-default"
LOG_GROUPS = [
    "/aws/lambda/archreviewagent-aws-docs",
    "/aws/lambda/archreviewagent-infra-modifier",
]
COGNITO_POOL_NAME = "archreview-demo-pool"


def _find_cognito_pool(client, pool_name: str) -> str | None:
    """Return the user pool ID matching pool_name, or None if not found."""
    paginator = client.get_paginator("list_user_pools")
    for page in paginator.paginate(MaxResults=60):
        for pool in page.get("UserPools", []):
            if pool["Name"] == pool_name:
                return pool["Id"]
    return None


def delete_cognito_pool(region: str) -> None:
    """Delete the Cognito user pool created by setup_cognito.py (if it exists)."""
    print("\n[4/4] Deleting Cognito user pool...")
    client = boto3.client("cognito-idp", region_name=region)

    pool_id = _find_cognito_pool(client, COGNITO_POOL_NAME)
    if not pool_id:
        print(f"  ℹ️  Cognito pool '{COGNITO_POOL_NAME}' not found, skipping.")
        return

    # Cognito requires deleting the domain (if any) before the pool
    try:
        pool_info = client.describe_user_pool(UserPoolId=pool_id)
        domain = pool_info["UserPool"].get("Domain")
        if domain:
            client.delete_user_pool_domain(UserPoolId=pool_id, Domain=domain)
            print(f"  🗑️  Deleted pool domain: {domain}")
    except ClientError:
        pass  # No domain or already deleted

    try:
        client.delete_user_pool(UserPoolId=pool_id)
        print(f"  🗑️  Deleted Cognito pool: {COGNITO_POOL_NAME} ({pool_id})")
    except ClientError as e:
        print(f"  ⚠️  Error deleting Cognito pool: {e}")


def delete_observability(region: str) -> None:
    """Delete CloudWatch Logs delivery resources created by deploy.py for observability.

    Scans for all delivery sources referencing this project's AgentCore resources
    and removes them (deliveries → destinations → sources) in the correct order.
    Must run BEFORE stack deletion since delivery sources reference resource ARNs.
    """
    print("\n[1/4] Deleting observability delivery resources...")
    logs_client = boto3.client("logs", region_name=region)

    # Find all delivery sources that reference our archreviewagent resources
    sources_to_delete = []
    try:
        resp = logs_client.describe_delivery_sources()
        for source in resp.get("deliverySources", []):
            resource_arns = source.get("resourceArns", [])
            name = source.get("name", "")
            # Match sources pointing to our runtime or gateway
            if any("archreviewagent" in arn for arn in resource_arns) or "archreview-" in name:
                sources_to_delete.append(name)
    except ClientError as e:
        print(f"  ⚠️  Could not list delivery sources: {e}")
        return

    if not sources_to_delete:
        print("  ℹ️  No observability delivery sources found, skipping.")
        return

    # Step 1: Delete all deliveries referencing these sources OR archreview destinations
    try:
        resp = logs_client.describe_deliveries()
        for delivery in resp.get("deliveries", []):
            source_match = delivery.get("deliverySourceName") in sources_to_delete
            dest_match = "archreview" in delivery.get("deliveryDestinationArn", "")
            if source_match or dest_match:
                try:
                    logs_client.delete_delivery(id=delivery["id"])
                    print(f"  🗑️  Deleted delivery: {delivery['id']}")
                except ClientError as e:
                    print(f"  ⚠️  Error deleting delivery {delivery['id']}: {e}")
    except ClientError:
        pass

    # Step 2: Delete delivery destinations associated with these sources
    failed_destinations = []
    try:
        resp = logs_client.describe_delivery_destinations()
        for dest in resp.get("deliveryDestinations", []):
            dest_name = dest.get("name", "")
            if "archreview" in dest_name:
                try:
                    logs_client.delete_delivery_destination(name=dest_name)
                    print(f"  🗑️  Deleted destination: {dest_name}")
                except ClientError as e:
                    if "ConflictException" in str(e):
                        failed_destinations.append(dest_name)
                    elif "ResourceNotFoundException" not in str(e):
                        print(f"  ⚠️  Error deleting destination {dest_name}: {e}")
    except ClientError:
        pass

    # Step 3: Delete delivery sources
    for source_name in sources_to_delete:
        try:
            logs_client.delete_delivery_source(name=source_name)
            print(f"  🗑️  Deleted source: {source_name}")
        except ClientError as e:
            if "ResourceNotFoundException" not in str(e):
                print(f"  ⚠️  Error deleting source {source_name}: {e}")

    # Step 3b: Retry failed destinations (their deliveries may now be gone after source deletion)
    for dest_name in failed_destinations:
        try:
            # First try to delete any remaining deliveries pointing to this destination
            resp = logs_client.describe_deliveries()
            for delivery in resp.get("deliveries", []):
                if dest_name in delivery.get("deliveryDestinationArn", ""):
                    logs_client.delete_delivery(id=delivery["id"])
                    print(f"  🗑️  Deleted lingering delivery: {delivery['id']}")
        except ClientError:
            pass
        try:
            logs_client.delete_delivery_destination(name=dest_name)
            print(f"  🗑️  Deleted destination (retry): {dest_name}")
        except ClientError as e:
            if "ResourceNotFoundException" not in str(e):
                print(f"  ⚠️  Could not delete destination {dest_name}: {e}")

    # Step 4: Delete vended log groups
    try:
        resp = logs_client.describe_log_groups(
            logGroupNamePrefix="/aws/vendedlogs/bedrock-agentcore/"
        )
        for lg in resp.get("logGroups", []):
            if "archreviewagent" in lg["logGroupName"]:
                logs_client.delete_log_group(logGroupName=lg["logGroupName"])
                print(f"  🗑️  Deleted log group: {lg['logGroupName']}")
    except ClientError:
        pass


def delete_log_groups(region: str) -> None:
    """Delete orphaned CloudWatch Log Groups."""
    print("\n[2/4] Deleting CloudWatch Log Groups...")
    client = boto3.client("logs", region_name=region)

    for log_group in LOG_GROUPS:
        try:
            client.delete_log_group(logGroupName=log_group)
            print(f"  🗑️  Deleted: {log_group}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                print(f"  ℹ️  Not found (already deleted): {log_group}")
            else:
                print(f"  ⚠️  Error deleting {log_group}: {e}")


def delete_cloudformation_stack(region: str) -> None:
    """Delete the CloudFormation stack and wait for completion."""
    print("\n[3/4] Deleting CloudFormation stack...")
    client = boto3.client("cloudformation", region_name=region)

    try:
        client.describe_stacks(StackName=STACK_NAME)
    except ClientError as e:
        if "does not exist" in str(e):
            print(f"  ℹ️  Stack '{STACK_NAME}' not found, skipping.")
            return
        raise

    try:
        client.delete_stack(StackName=STACK_NAME)
        print(f"  ⏳ Stack deletion initiated: {STACK_NAME}")
        print("  ⏳ Waiting for stack deletion to complete (this may take a few minutes)...")

        waiter = client.get_waiter("stack_delete_complete")
        waiter.wait(StackName=STACK_NAME, WaiterConfig={"Delay": 10, "MaxAttempts": 60})
        print(f"  ✅ Stack deleted: {STACK_NAME}")
    except ClientError as e:
        print(f"  ⚠️  Error deleting stack: {e}")
    except Exception:
        # The waiter raises on DELETE_FAILED. Surface which resource(s) failed
        # and why, so the user has an actionable next step instead of a generic
        # "may still be in progress" message.
        _report_delete_failure(client, region)


def _report_delete_failure(client, region: str) -> None:
    """Inspect a DELETE_FAILED stack and print the failed resources + guidance."""
    try:
        status = client.describe_stacks(StackName=STACK_NAME)["Stacks"][0]["StackStatus"]
    except ClientError:
        print(f"  ⚠️  Stack deletion did not complete. Check status:")
        print(f"     aws cloudformation describe-stacks --stack-name {STACK_NAME} --region {region}")
        return

    if status != "DELETE_FAILED":
        print(f"  ⚠️  Stack deletion did not complete (status: {status}). Check status:")
        print(f"     aws cloudformation describe-stacks --stack-name {STACK_NAME} --region {region}")
        return

    print(f"  ❌ Stack is in DELETE_FAILED. Resource(s) that could not be deleted:")
    try:
        events = client.describe_stack_events(StackName=STACK_NAME)["StackEvents"]
        seen = set()
        for ev in events:
            if ev.get("ResourceStatus") == "DELETE_FAILED":
                lid = ev.get("LogicalResourceId")
                if lid in seen or lid == STACK_NAME:
                    continue
                seen.add(lid)
                reason = ev.get("ResourceStatusReason", "") or ""
                print(f"       - {lid} ({ev.get('ResourceType')}): {reason[:200]}")
    except ClientError:
        pass

    print("\n  This usually means a resource has a lingering external dependency.")
    print("  Most common case: the AgentCore Runtime fails to delete because its")
    print("  JWT authorizer references a Cognito pool that was already removed.")
    print("  To recover:")
    print("    1. Delete the stuck runtime directly:")
    print("         aws bedrock-agentcore-control list-agent-runtimes --region "
          f"{region}")
    print("         aws bedrock-agentcore-control delete-agent-runtime "
          f"--agent-runtime-id <id> --region {region}")
    print(f"    2. Re-run: python cleanup.py --region {region}")


def main():
    parser = argparse.ArgumentParser(description="Cleanup Architecture Review Agent resources")
    parser.add_argument("--force", action="store_true", help="Skip confirmation prompts")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    args = parser.parse_args()

    # Check what exists before prompting
    cognito_client = boto3.client("cognito-idp", region_name=args.region)
    cognito_pool_id = _find_cognito_pool(cognito_client, COGNITO_POOL_NAME)

    print("=" * 60)
    print("  Architecture Review Agent - Cleanup")
    print("=" * 60)
    print(f"\n  Region: {args.region}")
    print(f"  Stack:  {STACK_NAME}")
    print(f"  Log Groups: {', '.join(LOG_GROUPS)}")
    if cognito_pool_id:
        print(f"  Cognito Pool: {COGNITO_POOL_NAME} ({cognito_pool_id})")
    else:
        print(f"  Cognito Pool: not found (nothing to delete)")

    if not args.force:
        print("\n⚠️  This will permanently delete all resources listed above")
        print("   (the stack includes the Policy Engine, Cedar policies, Gateway, and Memory).")
        response = input("   Continue? [y/N]: ").strip().lower()
        if response not in ("y", "yes"):
            print("\n  Cancelled.")
            sys.exit(0)

    delete_observability(args.region)
    delete_log_groups(args.region)
    delete_cloudformation_stack(args.region)
    delete_cognito_pool(args.region)  # last: the stack's runtime references the pool's discovery URL

    print("\n" + "=" * 60)
    print("  ✅ Cleanup complete!")
    print("=" * 60)
    print("\n  To deactivate the virtual environment: deactivate")
    print("  To redeploy: python deploy.py\n")


if __name__ == "__main__":
    main()

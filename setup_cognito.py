#!/usr/bin/env python3
"""Set up a Cognito user pool for AgentCore Runtime JWT (inbound) authentication.

This provisions the identity provider used to demonstrate AgentCore Identity:
only a developer holding a valid bearer token from this pool can invoke the
review agent. The agent runtime is configured (in agentcore.json) with a
CUSTOM_JWT authorizer pointing at this pool's OpenID Connect discovery URL.

Idempotent: re-running finds the existing pool/client/user by name instead of
creating duplicates.

Usage:
    python setup_cognito.py
    python setup_cognito.py --region us-east-1
    python setup_cognito.py --print-config   # just print pool/client/discovery

Outputs the values needed by agentcore.json:
    - discoveryUrl
    - allowedClients (the app client ID)
and the demo user credentials used by review.py to fetch a token.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"
POOL_NAME = "archreview-demo-pool"
CLIENT_NAME = "archreview-demo-client"
DEMO_USERNAME = os.environ.get("COGNITO_USERNAME", "well-architected-agent")


def _resolve_password() -> str:
    """Resolve the demo user's password without storing one in the repo.

    Uses $COGNITO_PASSWORD if set; otherwise generates a strong random password
    and prints it once so the operator can export it for review.py /
    review_async.py. No credential is hardcoded in this file.
    """
    env_pw = os.environ.get("COGNITO_PASSWORD")
    if env_pw:
        return env_pw
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    # Cognito default policy: 8+ chars with upper/lower/digit; add fixed symbol.
    return "".join(secrets.choice(alphabet) for _ in range(16)) + "!Aa1"


def _find_pool(client, pool_name: str) -> str | None:
    """Return the user pool ID matching pool_name, or None."""
    paginator = client.get_paginator("list_user_pools")
    for page in paginator.paginate(MaxResults=60):
        for pool in page.get("UserPools", []):
            if pool["Name"] == pool_name:
                return pool["Id"]
    return None


def _find_client(client, pool_id: str, client_name: str) -> str | None:
    """Return the app client ID matching client_name, or None."""
    paginator = client.get_paginator("list_user_pool_clients")
    for page in paginator.paginate(UserPoolId=pool_id, MaxResults=60):
        for c in page.get("UserPoolClients", []):
            if c["ClientName"] == client_name:
                return c["ClientId"]
    return None


def setup(region: str, print_only: bool = False) -> dict:
    client = boto3.client("cognito-idp", region_name=region)

    # 1. User pool
    pool_id = _find_pool(client, POOL_NAME)
    if pool_id:
        print(f"  Found existing user pool: {pool_id}")
    elif print_only:
        print("  (no pool yet — run without --print-config to create)", file=sys.stderr)
        sys.exit(1)
    else:
        pool_id = client.create_user_pool(
            PoolName=POOL_NAME,
            Policies={"PasswordPolicy": {"MinimumLength": 8}},
        )["UserPool"]["Id"]
        print(f"  Created user pool: {pool_id}")

    # 2. App client (no secret — USER_PASSWORD_AUTH for the demo)
    client_id = _find_client(client, pool_id, CLIENT_NAME)
    if client_id:
        print(f"  Found existing app client: {client_id}")
    elif not print_only:
        client_id = client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=CLIENT_NAME,
            GenerateSecret=False,
            ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        )["UserPoolClient"]["ClientId"]
        print(f"  Created app client: {client_id}")

    # 3. Demo user with a permanent password (resolved from env or generated;
    #    never hardcoded in this repo).
    demo_password = _resolve_password()
    if not print_only:
        try:
            client.admin_create_user(
                UserPoolId=pool_id,
                Username=DEMO_USERNAME,
                MessageAction="SUPPRESS",
                TemporaryPassword=demo_password,
            )
            print(f"  Created user: {DEMO_USERNAME}")
        except client.exceptions.UsernameExistsException:
            print(f"  User already exists: {DEMO_USERNAME}")
        client.admin_set_user_password(
            UserPoolId=pool_id,
            Username=DEMO_USERNAME,
            Password=demo_password,
            Permanent=True,
        )

    discovery_url = (
        f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration"
    )

    config = {
        "pool_id": pool_id,
        "client_id": client_id,
        "discovery_url": discovery_url,
        "demo_username": DEMO_USERNAME,
        "demo_password": demo_password,
        "region": region,
    }
    return config


def main():
    parser = argparse.ArgumentParser(description="Set up Cognito for AgentCore JWT auth")
    parser.add_argument("--region", default=REGION)
    parser.add_argument("--print-config", action="store_true",
                        help="Only look up and print existing config")
    args = parser.parse_args()

    print("Setting up Cognito user pool for AgentCore JWT auth...")
    config = setup(args.region, print_only=args.print_config)

    print("\n=== Configuration for agentcore.json (runtime authorizer) ===")
    print(json.dumps({
        "authorizerType": "CUSTOM_JWT",
        "authorizerConfiguration": {
            "customJwtAuthorizer": {
                "discoveryUrl": config["discovery_url"],
                "allowedClients": [config["client_id"]],
            }
        },
    }, indent=2))
    print("\n=== Export these so review.py / review_async.py can authenticate ===")
    print(f"  export COGNITO_CLIENT_ID={config['client_id']}")
    print(f"  export COGNITO_USERNAME={config['demo_username']}")
    print(f"  export COGNITO_PASSWORD=<stored securely — check .env file or $COGNITO_PASSWORD>")
    print("\n  (The password was supplied via $COGNITO_PASSWORD or generated for you;")
    print("   it is written to .env with restricted permissions. Never commit .env to git.)")


if __name__ == "__main__":
    main()

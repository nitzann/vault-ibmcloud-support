#!/bin/bash

# Demo setup script for IBM Cloud auth
set -e

echo "Enabling IBM Cloud auth method..."
./bin/vault auth enable ibmcloud || echo "Auth method already enabled"

echo "Configuring IBM Cloud auth backend..."
./bin/vault write auth/ibmcloud/config \
    iam_endpoint=https://iam.test.cloud.ibm.com \
    metadata_endpoint=http://169.254.169.254 \
    iam_client_timeout=30 \
    api_key=Jm9OCZjqSMgPF7AdH4E8JX5-t541xf17zcvscNOYS6-M \
    service_id=ServiceId-0e366429-b7f2-460f-85b4-48c9e0f2c404 \
    account_id=3984162373f8850d2f9c4a0a80942828

echo "Creating policies..."
./bin/vault policy write my-policy my-policy.hcl
./bin/vault policy write my-writer-policy my-writer-policy.hcl

echo "Creating role: my-service-role..."
./bin/vault write auth/ibmcloud/role/my-service-role \
    type=apikey \
    bound_account_id=3984162373f8850d2f9c4a0a80942828 \
    token_policies=my-policy \
    token_ttl=1h \
    token_max_ttl=24h \
    bound_access_group_ids=AccessGroupId-92230e14-0c4f-4cb5-be43-da56586a69f5

echo "Creating role: my-service-writer-role..."
./bin/vault write auth/ibmcloud/role/my-service-writer-role \
    type=apikey \
    bound_account_id=3984162373f8850d2f9c4a0a80942828 \
    token_policies=my-writer-policy \
    token_ttl=1h \
    token_max_ttl=24h \
    bound_access_group_ids=AccessGroupId-92230e14-0c4f-4cb5-be43-da56586a69f5

echo "Setup complete!"
echo ""
echo "Test authentication with:"
echo "  ./bin/vault login -method=ibmcloud role=my-service-writer-role type=apikey apikey=YOUR_API_KEY"

# Made with Bob

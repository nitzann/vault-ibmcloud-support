#!/bin/bash

# Restart Vault Dev Server with Debug Logging
# This script stops any running Vault server and starts a fresh one with debug logs

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

VAULT_BINARY="./bin/vault"
VAULT_DEV_ROOT_TOKEN="root"
VAULT_ADDR="http://127.0.0.1:8200"

echo -e "${BLUE}Stopping any running Vault servers...${NC}"
pkill -f "vault server" 2>/dev/null || echo "No Vault server was running"
sleep 2

echo -e "${BLUE}Starting Vault dev server with DEBUG logging...${NC}"
echo -e "${BLUE}Root token: ${VAULT_DEV_ROOT_TOKEN}${NC}"
echo -e "${BLUE}Address: ${VAULT_ADDR}${NC}"

# Start Vault in background with debug log level
VAULT_LOG_LEVEL=debug ${VAULT_BINARY} server -dev \
    -dev-root-token-id="${VAULT_DEV_ROOT_TOKEN}" \
    -log-level=debug \
    > /tmp/vault-dev-debug.log 2>&1 &
VAULT_PID=$!

echo -e "${BLUE}Vault PID: ${VAULT_PID}${NC}"
echo -e "${BLUE}Waiting for Vault to start...${NC}"
sleep 5

# Set environment variables
export VAULT_ADDR="${VAULT_ADDR}"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN}"

# Verify Vault is running (allow unsealed or sealed status)
if ${VAULT_BINARY} status 2>&1 | grep -q "Sealed.*false\|Initialized.*true"; then
    echo -e "${GREEN}✓ Vault dev server is running with DEBUG logging!${NC}"
    echo ""
    echo "Environment variables:"
    echo "  export VAULT_ADDR='${VAULT_ADDR}'"
    echo "  export VAULT_TOKEN='${VAULT_DEV_ROOT_TOKEN}'"
    echo ""
    echo -e "${YELLOW}Debug logs: /tmp/vault-dev-debug.log${NC}"
    echo ""
    echo "To watch logs in real-time:"
    echo "  tail -f /tmp/vault-dev-debug.log"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Enable IBM Cloud auth: ${VAULT_BINARY} auth enable ibmcloud"
    echo "  2. Configure: ${VAULT_BINARY} write auth/ibmcloud/config iam_endpoint=https://iam.cloud.ibm.com"
    echo "  3. Create role: ${VAULT_BINARY} write auth/ibmcloud/role/my-role type=apikey ..."
    echo "  4. Test login: ${VAULT_BINARY} login -method=ibmcloud role=my-role type=apikey apikey=\$IBMCLOUD_API_KEY"
    echo ""
    echo -e "${YELLOW}The debug logs will show:${NC}"
    echo "  - All IAM API calls with full URLs"
    echo "  - Request headers and payloads"
    echo "  - Response status codes and bodies"
    echo "  - Service ID being used"
    echo "  - Token claims extracted"
else
    echo -e "${RED}✗ Failed to start Vault dev server${NC}"
    echo "Check logs: cat /tmp/vault-dev-debug.log"
    exit 1
fi

# Made with Bob

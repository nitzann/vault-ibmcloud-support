#!/bin/bash

# Build Vault with IBM Cloud auth support
# This script ensures the binary includes the ibmcloud CLI handler

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Building Vault with IBM Cloud auth support...${NC}"

# Ensure we're in the Vault directory
if [ ! -f "main.go" ] || [ ! -d "vault" ]; then
    echo -e "${RED}Error: This doesn't appear to be a Vault repository${NC}"
    echo "Please run this script from the root of the Vault repository"
    exit 1
fi

# Set Go environment
export CGO_ENABLED=0
export BUILD_TAGS="testonly"

# Ensure BUILD_MINIMAL is not set (we want the full build with all auth methods)
unset BUILD_MINIMAL

# Skip code generation since generated files are already committed
export SKIP_GEN=1

echo -e "${BLUE}Building Vault binary (skipping code generation)...${NC}"
make dev

# Verify the binary was created
if [ -f "bin/vault" ]; then
    echo -e "${GREEN}✓ Vault binary built successfully!${NC}"
    echo -e "${BLUE}Binary location: $(pwd)/bin/vault${NC}"
    echo -e "${BLUE}Version: $(bin/vault version)${NC}"
    
    # Verify ibmcloud auth is available
    echo ""
    echo -e "${BLUE}Verifying ibmcloud auth method is available...${NC}"
    if bin/vault auth help ibmcloud &>/dev/null; then
        echo -e "${GREEN}✓ IBM Cloud auth method is available in the CLI!${NC}"
    else
        echo -e "${RED}✗ IBM Cloud auth method not found in CLI${NC}"
        echo "This might indicate a build issue"
    fi
else
    echo -e "${RED}✗ Failed to build Vault binary${NC}"
    exit 1
fi

# Cross-compile the Linux binary used by deploy-vault-to-vsi.sh.
# Not executed here (host is not Linux), so no verification is run on it.
LINUX_BINARY="bin/vault-linux-amd64"
echo ""
echo -e "${BLUE}Building Linux amd64 binary for VSI deployment...${NC}"
GIT_COMMIT="$(scripts/ci-helper.sh revision)"
GIT_DIRTY="$(test -n "$(git status --porcelain)" && echo "+CHANGES" || true)"
BUILD_DATE="$(scripts/ci-helper.sh date)"
rm -f "${LINUX_BINARY}"
GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X github.com/hashicorp/vault/version.GitCommit='${GIT_COMMIT}${GIT_DIRTY}' -X github.com/hashicorp/vault/version.BuildDate=${BUILD_DATE}" \
    -o "${LINUX_BINARY}" \
    -tags "${BUILD_TAGS}" \
    ./command/server/cmd

if [ -f "${LINUX_BINARY}" ]; then
    echo -e "${GREEN}✓ Linux binary built: $(pwd)/${LINUX_BINARY}${NC}"
else
    echo -e "${RED}✗ Failed to build Linux binary${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Build complete!${NC}"
echo ""
echo "To use this binary:"
echo "  export PATH=$(pwd)/bin:\$PATH"
echo ""
echo "Or run directly:"
echo "  $(pwd)/bin/vault login -method=ibmcloud role=my-role type=apikey apikey=\$IBMCLOUD_API_KEY"

# Made with Bob

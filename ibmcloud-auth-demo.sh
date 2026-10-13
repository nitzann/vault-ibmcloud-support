#!/bin/bash

# IBM Cloud IAM Authentication Demo Script
# This script demonstrates the IBM Cloud authentication method for HashiCorp Vault
# It builds Vault from source and walks through the authentication flows

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VAULT_DIR="$(pwd)"
VAULT_DEV_ROOT_TOKEN="root"
VAULT_ADDR="http://127.0.0.1:8200"
VAULT_BINARY="${VAULT_DIR}/bin/vault"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}ℹ ${1}${NC}"
}

print_success() {
    echo -e "${GREEN}✓ ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ ${1}${NC}"
}

print_error() {
    echo -e "${RED}✗ ${1}${NC}"
}

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  ${1}${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    local missing_deps=()
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        missing_deps+=("go (https://golang.org/dl/)")
    else
        print_success "Go is installed: $(go version)"
    fi
    
    # Check for Git
    if ! command -v git &> /dev/null; then
        missing_deps+=("git")
    else
        print_success "Git is installed: $(git --version)"
    fi
    
    # Check for Make
    if ! command -v make &> /dev/null; then
        missing_deps+=("make")
    else
        print_success "Make is installed"
    fi
    
    # Check for jq (optional but recommended)
    if ! command -v jq &> /dev/null; then
        print_warning "jq is not installed (optional, but recommended for JSON parsing)"
    else
        print_success "jq is installed"
    fi
    
    # Check for IBM Cloud CLI (optional)
    if ! command -v ibmcloud &> /dev/null; then
        print_warning "IBM Cloud CLI is not installed (optional, needed for some operations)"
        print_info "Install from: https://cloud.ibm.com/docs/cli"
    else
        print_success "IBM Cloud CLI is installed: $(ibmcloud version)"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        exit 1
    fi
    
    print_success "All required prerequisites are met!"
}

# Function to build Vault from source
build_vault() {
    print_header "Building Vault from Source"
    
    print_info "Current directory: ${VAULT_DIR}"
    
    # Check if we're in a Vault repository
    if [ ! -f "main.go" ] || [ ! -d "vault" ]; then
        print_error "This doesn't appear to be a Vault repository"
        print_info "Please run this script from the root of the Vault repository"
        exit 1
    fi
    
    print_info "Building Vault (skipping code generation)..."
    print_info "Generated files are already committed to the repository"
    if SKIP_GEN=1 make dev; then
        print_success "Vault built successfully!"
    else
        print_error "Failed to build Vault"
        print_info "If you see 'enumer' errors, this is expected - we skip code generation"
        exit 1
    fi
    
    # Verify the binary exists
    if [ ! -f "${VAULT_BINARY}" ]; then
        print_error "Vault binary not found at ${VAULT_BINARY}"
        exit 1
    fi
    
    print_success "Vault binary location: ${VAULT_BINARY}"
    print_info "Vault version: $(${VAULT_BINARY} version)"
}

# Function to start Vault dev server
start_vault_dev_server() {
    print_header "Starting Vault Dev Server"
    
    # Check if Vault is already running
    if pgrep -f "vault server" > /dev/null; then
        print_warning "Vault server is already running"
        read -p "Do you want to kill it and start fresh? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            pkill -f "vault server"
            sleep 2
        else
            print_info "Using existing Vault server"
            return
        fi
    fi
    
    print_info "Starting Vault in dev mode..."
    print_info "Root token: ${VAULT_DEV_ROOT_TOKEN}"
    print_info "Address: ${VAULT_ADDR}"
    
    # Start Vault in background
    ${VAULT_BINARY} server -dev -dev-root-token-id="${VAULT_DEV_ROOT_TOKEN}" > /tmp/vault-dev.log 2>&1 &
    VAULT_PID=$!
    
    # Wait for Vault to start
    print_info "Waiting for Vault to start..."
    sleep 3
    
    # Verify Vault is running
    export VAULT_ADDR="${VAULT_ADDR}"
    export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN}"
    
    if ${VAULT_BINARY} status > /dev/null 2>&1; then
        print_success "Vault dev server is running (PID: ${VAULT_PID})"
        print_info "Logs: /tmp/vault-dev.log"
    else
        print_error "Failed to start Vault dev server"
        cat /tmp/vault-dev.log
        exit 1
    fi
}

# Function to enable IBM Cloud auth method
enable_ibmcloud_auth() {
    print_header "Enabling IBM Cloud Auth Method"
    
    # Check if already enabled
    if ${VAULT_BINARY} auth list | grep -q "ibmcloud/"; then
        print_warning "IBM Cloud auth method is already enabled"
        return
    fi
    
    print_info "Enabling IBM Cloud auth method..."
    if ${VAULT_BINARY} auth enable ibmcloud; then
        print_success "IBM Cloud auth method enabled!"
    else
        print_error "Failed to enable IBM Cloud auth method"
        print_info "This is expected if the implementation is not yet complete"
        print_warning "The auth method will be available once the code is implemented"
        return 1
    fi
}

# Function to configure IBM Cloud auth backend
configure_ibmcloud_auth() {
    print_header "Configuring IBM Cloud Auth Backend"
    
    print_info "Setting default configuration..."
    
    # Configure with default endpoints
    if ${VAULT_BINARY} write auth/ibmcloud/config \
        iam_endpoint="https://iam.cloud.ibm.com" \
        metadata_endpoint="http://169.254.169.254" \
        iam_client_timeout=30; then
        print_success "IBM Cloud auth backend configured!"
    else
        print_warning "Failed to configure backend (expected if not yet implemented)"
        return 1
    fi
    
    # Read back configuration
    print_info "Reading configuration..."
    ${VAULT_BINARY} read auth/ibmcloud/config || true
}

# Function to create API Key role
create_apikey_role() {
    print_header "Creating API Key Role"
    
    local role_name="${1:-demo-apikey-role}"
    local account_id="${2}"
    
    if [ -z "$account_id" ]; then
        print_info "No account ID provided, using placeholder"
        account_id="abc123def456"
    fi
    
    print_info "Creating role: ${role_name}"
    print_info "Account ID: ${account_id}"
    
    if ${VAULT_BINARY} write auth/ibmcloud/role/${role_name} \
        type=apikey \
        bound_account_id="${account_id}" \
        token_policies="default" \
        token_ttl="1h" \
        token_max_ttl="24h"; then
        print_success "API Key role created: ${role_name}"
    else
        print_warning "Failed to create role (expected if not yet implemented)"
        return 1
    fi
    
    # Read back the role
    print_info "Reading role configuration..."
    ${VAULT_BINARY} read auth/ibmcloud/role/${role_name} || true
}

# Function to create Trusted Profile role
create_trusted_profile_role() {
    print_header "Creating Trusted Profile Role"
    
    local role_name="${1:-demo-profile-role}"
    local profile_id="${2}"
    
    if [ -z "$profile_id" ]; then
        print_info "No profile ID provided, using placeholder"
        profile_id="Profile-12345678-1234-1234-1234-123456789012"
    fi
    
    print_info "Creating role: ${role_name}"
    print_info "Trusted Profile ID: ${profile_id}"
    
    if ${VAULT_BINARY} write auth/ibmcloud/role/${role_name} \
        type=trusted_profile \
        bound_trusted_profile_id="${profile_id}" \
        bound_compute_resource_crn="crn:v1:bluemix:public:is:*:a/*::instance:*" \
        token_policies="default" \
        token_ttl="1h" \
        token_max_ttl="24h"; then
        print_success "Trusted Profile role created: ${role_name}"
    else
        print_warning "Failed to create role (expected if not yet implemented)"
        return 1
    fi
    
    # Read back the role
    print_info "Reading role configuration..."
    ${VAULT_BINARY} read auth/ibmcloud/role/${role_name} || true
}

# Function to test API Key authentication
test_apikey_auth() {
    print_header "Testing API Key Authentication"
    
    local role_name="${1:-demo-apikey-role}"
    local api_key="${2}"
    
    if [ -z "$api_key" ]; then
        print_warning "No API key provided"
        print_info "To test with a real API key, run:"
        print_info "  export IBMCLOUD_API_KEY='your-api-key'"
        print_info "  $0 --test-apikey"
        return 1
    fi
    
    print_info "Attempting to authenticate with API key..."
    print_info "Role: ${role_name}"
    
    # Unset root token to test authentication
    unset VAULT_TOKEN
    
    if ${VAULT_BINARY} login -method=ibmcloud \
        role="${role_name}" \
        type=apikey \
        apikey="${api_key}"; then
        print_success "API Key authentication successful!"
        
        # Show token info
        print_info "Token information:"
        ${VAULT_BINARY} token lookup
    else
        print_error "API Key authentication failed"
        print_info "This is expected if:"
        print_info "  1. The implementation is not yet complete"
        print_info "  2. The API key is invalid"
        print_info "  3. The account ID doesn't match the role binding"
    fi
    
    # Restore root token
    export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN}"
}

# Function to test Trusted Profile authentication
test_trusted_profile_auth() {
    print_header "Testing Trusted Profile Authentication"
    
    local role_name="${1:-demo-profile-role}"
    
    print_info "Checking if running on IBM Cloud compute resource..."
    
    # Check if metadata service is available
    if curl -s -m 2 -X PUT "http://169.254.169.254/instance_identity/v1/token" \
        -H "Metadata-Flavor: ibm" \
        -d '{"expires_in": 3600}' > /dev/null 2>&1; then
        print_success "VPC metadata service is available!"
        
        print_info "Attempting to authenticate with Trusted Profile..."
        print_info "Role: ${role_name}"
        
        # Unset root token to test authentication
        unset VAULT_TOKEN
        
        if ${VAULT_BINARY} login -method=ibmcloud \
            role="${role_name}" \
            type=trusted_profile; then
            print_success "Trusted Profile authentication successful!"
            
            # Show token info
            print_info "Token information:"
            ${VAULT_BINARY} token lookup
        else
            print_error "Trusted Profile authentication failed"
        fi
        
        # Restore root token
        export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN}"
    else
        print_warning "VPC metadata service is not available"
        print_info "This is expected if you're not running on an IBM Cloud VPC instance"
        print_info "To test Trusted Profile authentication:"
        print_info "  1. Deploy this script to a VPC instance"
        print_info "  2. Attach a Trusted Profile to the instance"
        print_info "  3. Run: $0 --test-profile"
    fi
}

# Function to demonstrate Vault Agent with API Key
demo_vault_agent_apikey() {
    print_header "Demonstrating Vault Agent with API Key"
    
    local api_key="${1}"
    
    if [ -z "$api_key" ]; then
        print_warning "No API key provided"
        print_info "Set IBMCLOUD_API_KEY environment variable to test"
        return 1
    fi
    
    # Create agent config
    local config_file="/tmp/vault-agent-apikey.hcl"
    
    print_info "Creating Vault Agent configuration..."
    cat > "${config_file}" << EOF
vault {
  address = "${VAULT_ADDR}"
}

auto_auth {
  method {
    type = "ibmcloud"
    
    config = {
      role   = "demo-apikey-role"
      type   = "apikey"
      apikey = "${api_key}"
    }
  }
  
  sink {
    type = "file"
    config = {
      path = "/tmp/vault-token-apikey"
    }
  }
}
EOF
    
    print_success "Agent configuration created: ${config_file}"
    cat "${config_file}"
    
    print_info "Starting Vault Agent..."
    ${VAULT_BINARY} agent -config="${config_file}" &
    AGENT_PID=$!
    
    print_info "Agent PID: ${AGENT_PID}"
    print_info "Waiting for authentication..."
    sleep 5
    
    if [ -f "/tmp/vault-token-apikey" ]; then
        print_success "Token written to /tmp/vault-token-apikey"
        print_info "Token content:"
        cat /tmp/vault-token-apikey
        echo ""
    else
        print_warning "Token file not created (expected if not yet implemented)"
    fi
    
    # Stop agent
    kill ${AGENT_PID} 2>/dev/null || true
    print_info "Agent stopped"
}

# Function to demonstrate Vault Agent with Trusted Profile
demo_vault_agent_profile() {
    print_header "Demonstrating Vault Agent with Trusted Profile"
    
    # Check if metadata service is available
    if ! curl -s -m 2 -X PUT "http://169.254.169.254/instance_identity/v1/token" \
        -H "Metadata-Flavor: ibm" \
        -d '{"expires_in": 3600}' > /dev/null 2>&1; then
        print_warning "VPC metadata service is not available"
        print_info "This demo requires running on an IBM Cloud VPC instance"
        return 1
    fi
    
    # Create agent config
    local config_file="/tmp/vault-agent-profile.hcl"
    
    print_info "Creating Vault Agent configuration..."
    cat > "${config_file}" << EOF
vault {
  address = "${VAULT_ADDR}"
}

auto_auth {
  method {
    type = "ibmcloud"
    
    config = {
      role = "demo-profile-role"
      type = "trusted_profile"
      credential_poll_interval = 60
    }
  }
  
  sink {
    type = "file"
    config = {
      path = "/tmp/vault-token-profile"
    }
  }
}
EOF
    
    print_success "Agent configuration created: ${config_file}"
    cat "${config_file}"
    
    print_info "Starting Vault Agent..."
    ${VAULT_BINARY} agent -config="${config_file}" &
    AGENT_PID=$!
    
    print_info "Agent PID: ${AGENT_PID}"
    print_info "Waiting for authentication..."
    sleep 5
    
    if [ -f "/tmp/vault-token-profile" ]; then
        print_success "Token written to /tmp/vault-token-profile"
        print_info "Token content:"
        cat /tmp/vault-token-profile
        echo ""
    else
        print_warning "Token file not created (expected if not yet implemented)"
    fi
    
    # Stop agent
    kill ${AGENT_PID} 2>/dev/null || true
    print_info "Agent stopped"
}

# Function to get IBM Cloud account info
get_ibmcloud_info() {
    print_header "Getting IBM Cloud Account Information"
    
    if ! command -v ibmcloud &> /dev/null; then
        print_warning "IBM Cloud CLI is not installed"
        print_info "Install from: https://cloud.ibm.com/docs/cli"
        return 1
    fi
    
    print_info "Checking IBM Cloud CLI login status..."
    if ! ibmcloud account show &> /dev/null; then
        print_warning "Not logged in to IBM Cloud CLI"
        print_info "Run: ibmcloud login"
        return 1
    fi
    
    print_success "IBM Cloud CLI is logged in"
    
    print_info "Account information:"
    ibmcloud account show
    
    print_info "Getting account ID..."
    ACCOUNT_ID=$(ibmcloud account show --output json | jq -r '.account_id' 2>/dev/null || echo "")
    
    if [ -n "$ACCOUNT_ID" ]; then
        print_success "Account ID: ${ACCOUNT_ID}"
        export IBMCLOUD_ACCOUNT_ID="${ACCOUNT_ID}"
    fi
}

# Function to create IBM Cloud API key
create_ibmcloud_apikey() {
    print_header "Creating IBM Cloud API Key"
    
    if ! command -v ibmcloud &> /dev/null; then
        print_warning "IBM Cloud CLI is not installed"
        return 1
    fi
    
    if ! ibmcloud account show &> /dev/null; then
        print_warning "Not logged in to IBM Cloud CLI"
        return 1
    fi
    
    local key_name="vault-demo-$(date +%s)"
    
    print_info "Creating API key: ${key_name}"
    print_warning "Save this API key securely - you won't be able to see it again!"
    
    ibmcloud iam api-key-create "${key_name}" --output json
    
    print_info "To use this API key with Vault:"
    print_info "  export IBMCLOUD_API_KEY='your-api-key-here'"
}

# Function to cleanup
cleanup() {
    print_header "Cleanup"
    
    print_info "Stopping Vault dev server..."
    pkill -f "vault server" 2>/dev/null || true
    
    print_info "Removing temporary files..."
    rm -f /tmp/vault-token-apikey /tmp/vault-token-profile
    rm -f /tmp/vault-agent-apikey.hcl /tmp/vault-agent-profile.hcl
    
    print_success "Cleanup complete"
}

# Function to show usage
show_usage() {
    cat << EOF
IBM Cloud IAM Authentication Demo Script

Usage: $0 [OPTIONS]

OPTIONS:
    --build                 Build Vault from source
    --start                 Start Vault dev server
    --setup                 Enable and configure IBM Cloud auth
    --create-roles          Create demo roles
    --test-apikey           Test API key authentication
    --test-profile          Test Trusted Profile authentication
    --demo-agent-apikey     Demo Vault Agent with API key
    --demo-agent-profile    Demo Vault Agent with Trusted Profile
    --ibmcloud-info         Get IBM Cloud account information
    --create-apikey         Create IBM Cloud API key
    --full-demo             Run complete demo (build, setup, create roles)
    --cleanup               Stop Vault and cleanup
    --help                  Show this help message

ENVIRONMENT VARIABLES:
    IBMCLOUD_API_KEY        IBM Cloud API key for testing
    IBMCLOUD_ACCOUNT_ID     IBM Cloud account ID for role creation
    VAULT_ADDR              Vault server address (default: http://127.0.0.1:8200)

EXAMPLES:
    # Full demo (build and setup)
    $0 --full-demo

    # Test with your API key
    export IBMCLOUD_API_KEY='your-api-key'
    $0 --test-apikey

    # Get IBM Cloud info and create API key
    $0 --ibmcloud-info
    $0 --create-apikey

    # Cleanup
    $0 --cleanup

NOTES:
    - This script must be run from the root of the Vault repository
    - The IBM Cloud auth method must be implemented for full functionality
    - Some features require IBM Cloud CLI to be installed and configured
    - Trusted Profile authentication requires running on IBM Cloud VPC instance

EOF
}

# Main script logic
main() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 0
    fi
    
    # Process each argument
    while [ $# -gt 0 ]; do
        case "$1" in
            --build)
                check_prerequisites
                build_vault
                ;;
            --start)
                start_vault_dev_server
                ;;
            --setup)
                enable_ibmcloud_auth
                configure_ibmcloud_auth
                ;;
            --create-roles)
                create_apikey_role "demo-apikey-role" "${IBMCLOUD_ACCOUNT_ID}"
                create_trusted_profile_role "demo-profile-role"
                ;;
            --test-apikey)
                test_apikey_auth "demo-apikey-role" "${IBMCLOUD_API_KEY}"
                ;;
            --test-profile)
                test_trusted_profile_auth "demo-profile-role"
                ;;
            --demo-agent-apikey)
                demo_vault_agent_apikey "${IBMCLOUD_API_KEY}"
                ;;
            --demo-agent-profile)
                demo_vault_agent_profile
                ;;
            --ibmcloud-info)
                get_ibmcloud_info
                ;;
            --create-apikey)
                create_ibmcloud_apikey
                ;;
            --full-demo)
                check_prerequisites
                build_vault
                start_vault_dev_server
                sleep 2
                enable_ibmcloud_auth || print_warning "Auth method not yet implemented"
                configure_ibmcloud_auth || print_warning "Configuration not yet available"
                create_apikey_role "demo-apikey-role" "${IBMCLOUD_ACCOUNT_ID}" || print_warning "Role creation not yet available"
                create_trusted_profile_role "demo-profile-role" || print_warning "Role creation not yet available"
                print_success "Full demo setup complete!"
                print_info "Next steps:"
                print_info "  1. Set IBMCLOUD_API_KEY environment variable"
                print_info "  2. Run: $0 --test-apikey"
                ;;
            --cleanup)
                cleanup
                ;;
            --help)
                show_usage
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
        shift
    done
}

# Run main function
main "$@"

# Made with Bob

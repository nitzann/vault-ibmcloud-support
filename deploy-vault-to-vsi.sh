#!/bin/bash

set -euo pipefail

REMOTE_HOST="vpcuser@169.59.209.194"
SSH_KEY="nn-ssh_rsa.prv"
REMOTE_DIR="/home/vpcuser/vault-ibmcloud-demo"
REMOTE_BIN_DIR="${REMOTE_DIR}/bin"
REMOTE_LOG_DIR="${REMOTE_DIR}/logs"
REMOTE_DATA_DIR="${REMOTE_DIR}/data"
REMOTE_CONFIG_DIR="${REMOTE_DIR}/config"
REMOTE_PID_FILE="${REMOTE_DIR}/vault.pid"
REMOTE_ENV_FILE="${REMOTE_DIR}/vault.env"
LOCAL_VAULT_BINARY="bin/vault-linux-amd64"
SSH_OPTS=(-i "${SSH_KEY}" -o StrictHostKeyChecking=accept-new)
# Optional: IAM trusted profile ID to bind the Vault roles to.
# If empty, it is detected from the VSI instance metadata.
TRUSTED_PROFILE_ID="${TRUSTED_PROFILE_ID:-}"

# Parse flags
TESTS_ONLY=false
for arg in "$@"; do
    case "${arg}" in
        --tests-only) TESTS_ONLY=true ;;
        *) echo "Unknown argument: ${arg}"; echo "Usage: $0 [--tests-only]"; exit 1 ;;
    esac
done

if [ ! -f "${SSH_KEY}" ]; then
    echo "Error: SSH key not found: ${SSH_KEY}"
    exit 1
fi

chmod 600 "${SSH_KEY}"

KNOWN_HOSTS_FILE="${HOME}/.ssh/known_hosts"
if [ -f "${KNOWN_HOSTS_FILE}" ]; then
    ssh-keygen -R "169.59.209.194" -f "${KNOWN_HOSTS_FILE}" >/dev/null 2>&1 || true
    ssh-keygen -R "[169.59.209.194]:22" -f "${KNOWN_HOSTS_FILE}" >/dev/null 2>&1 || true
fi

if [ "${TESTS_ONLY}" = false ] && [ ! -f "${LOCAL_VAULT_BINARY}" ]; then
    echo "Error: Vault binary not found: ${LOCAL_VAULT_BINARY}"
    echo "Build it first with ./build-vault-with-ibmcloud.sh"
    exit 1
fi

shopt -s nullglob
ROOT_SH_FILES=(./*.sh)
ROOT_HCL_FILES=(./*.hcl)
shopt -u nullglob

COPY_FILES=("${ROOT_SH_FILES[@]}" "${ROOT_HCL_FILES[@]}")

cat <<EOF
Deploying Vault demo assets to VSI
  Host: ${REMOTE_HOST}
  SSH key: ${SSH_KEY}
  Remote dir: ${REMOTE_DIR}
  Vault binary: ${LOCAL_VAULT_BINARY}
  Mode: $([ "${TESTS_ONLY}" = true ] && echo "tests-only (skip binary copy and Vault restart)" || echo "full deploy")
EOF

echo "Creating remote directories..."
ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "\
    mkdir -p '${REMOTE_BIN_DIR}' '${REMOTE_LOG_DIR}' '${REMOTE_DATA_DIR}' '${REMOTE_CONFIG_DIR}'"

if [ "${TESTS_ONLY}" = false ]; then
    echo "Copying Vault binary..."
    scp "${SSH_OPTS[@]}" "${LOCAL_VAULT_BINARY}" "${REMOTE_HOST}:${REMOTE_BIN_DIR}/vault"
fi

if [ ${#COPY_FILES[@]} -gt 0 ]; then
    echo "Copying root .sh and .hcl files..."
    scp "${SSH_OPTS[@]}" "${COPY_FILES[@]}" "${REMOTE_HOST}:${REMOTE_DIR}/"
fi

echo "Creating trusted profile setup script on remote host..."
ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "cat > '${REMOTE_DIR}/demo-trusted-profile-setup.sh' <<'EOF'
#!/bin/bash

set -euo pipefail

cd \"\$(dirname \"\$0\")\"

VAULT_BIN=\"./bin/vault\"
VAULT_ADDR=\"\${VAULT_ADDR:-http://127.0.0.1:8200}\"
VAULT_TOKEN=\"\${VAULT_TOKEN:-root}\"
METADATA_URL=\"http://169.254.169.254\"

export VAULT_ADDR
export VAULT_TOKEN

if [ ! -x \"\${VAULT_BIN}\" ]; then
    echo \"Error: Vault binary not found at \${VAULT_BIN}\"
    exit 1
fi

PROFILE_ID=\"\${TRUSTED_PROFILE_ID:-}\"

if [ -n \"\${PROFILE_ID}\" ]; then
    echo \"Using trusted profile ID from TRUSTED_PROFILE_ID: \${PROFILE_ID}\"
else
    echo \"TRUSTED_PROFILE_ID not set, detecting trusted profile from instance metadata...\"
    echo \"Fetching VSI identity token...\"
    IDENTITY_TOKEN_RESPONSE=\$(curl -sS -X PUT \"\${METADATA_URL}/identity/v1/token?version=2025-08-26\" \
        -H \"Metadata-Flavor: ibm\" \
        -H \"Content-Type: application/json\" \
        -d '{\"expires_in\": 3600}')

    IDENTITY_TOKEN=\$(printf '%s' \"\${IDENTITY_TOKEN_RESPONSE}\" | sed -n 's/.*\"access_token\":\"\\([^\"]*\\)\".*/\\1/p')

    if [ -z \"\${IDENTITY_TOKEN}\" ]; then
        echo \"Error: Failed to obtain identity token from VSI metadata service\"
        echo \"Token response: \${IDENTITY_TOKEN_RESPONSE}\"
        exit 1
    fi

    echo \"Fetching instance metadata...\"
    INSTANCE_METADATA=\$(curl -sS \"\${METADATA_URL}/metadata/v1/instance?version=2025-08-26\" \
        -H \"Authorization: Bearer \${IDENTITY_TOKEN}\" \
        -H \"Metadata-Flavor: ibm\")

    PROFILE_ID=\$(printf '%s' \"\${INSTANCE_METADATA}\" | sed -n \
        -e 's/.*\"trusted_profile\"[^{]*{[^}]*\"id\":\"\\([^\"]*\\)\".*/\\1/p' \
        -e 's/.*\"profile\"[^{]*{[^}]*\"id\":\"\\([^\"]*\\)\".*/\\1/p')

    if [ -z \"\${PROFILE_ID}\" ]; then
        echo \"Error: Failed to determine attached trusted profile ID from instance metadata\"
        echo \"Set TRUSTED_PROFILE_ID when running deploy-vault-to-vsi.sh to provide it explicitly.\"
        echo \"Instance metadata response: \${INSTANCE_METADATA}\"
        exit 1
    fi

    echo \"Detected trusted profile ID: \${PROFILE_ID}\"
fi

echo \"Enabling IBM Cloud auth method...\"
if \"\${VAULT_BIN}\" auth list -format=json | grep -q '\"ibmcloud/\"'; then
    echo \"Auth method already enabled\"
else
    \"\${VAULT_BIN}\" auth enable ibmcloud
fi

echo \"Configuring IBM Cloud auth backend...\"
\"\${VAULT_BIN}\" write auth/ibmcloud/config \
    iam_endpoint=https://iam.test.cloud.ibm.com \
    metadata_endpoint=http://169.254.169.254 \
    iam_client_timeout=30

echo \"Creating policies from root HCL files that contain Vault path stanzas...\"
for policy_file in ./*.hcl; do
    [ -f \"\${policy_file}\" ] || continue
    if ! grep -qE '^[[:space:]]*path[[:space:]]*\"' \"\${policy_file}\"; then
        echo \"Skipping \${policy_file}: not a Vault policy (no path stanza)\"
        continue
    fi
    policy_name=\$(basename \"\${policy_file}\" .hcl)
    echo \"Writing policy: \${policy_name} from \${policy_file}\"
    \"\${VAULT_BIN}\" policy write \"\${policy_name}\" \"\${policy_file}\"
done

echo \"Creating role: my-service-role...\"
\"\${VAULT_BIN}\" write auth/ibmcloud/role/my-service-role \
    type=trusted_profile \
    bound_trusted_profile_id=\"\${PROFILE_ID}\" \
    token_policies=my-policy \
    token_ttl=1h \
    token_max_ttl=24h

echo \"Creating role: my-service-writer-role...\"
\"\${VAULT_BIN}\" write auth/ibmcloud/role/my-service-writer-role \
    type=trusted_profile \
    bound_trusted_profile_id=\"\${PROFILE_ID}\" \
    token_policies=my-writer-policy \
    token_ttl=1h \
    token_max_ttl=24h

echo \"Trusted profile setup complete!\"
echo
echo \"Test authentication with:\"
echo \"  ./bin/vault login -method=ibmcloud role=my-service-writer-role type=trusted_profile\"
EOF
chmod +x '${REMOTE_DIR}/demo-trusted-profile-setup.sh'"

echo "Preparing remote Vault environment file..."
REMOTE_ENV_CONTENT="export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root"
if [ -n "${TRUSTED_PROFILE_ID}" ]; then
    echo "  Using TRUSTED_PROFILE_ID=${TRUSTED_PROFILE_ID}"
    REMOTE_ENV_CONTENT="${REMOTE_ENV_CONTENT}
export TRUSTED_PROFILE_ID='${TRUSTED_PROFILE_ID}'"
fi
ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "cat > '${REMOTE_ENV_FILE}' <<'EOF'
${REMOTE_ENV_CONTENT}
EOF"

if [ "${TESTS_ONLY}" = false ]; then
    echo "Starting Vault dev server on remote host..."
    ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "\
        chmod +x '${REMOTE_BIN_DIR}/vault' '${REMOTE_DIR}'/*.sh && \
        if [ -f '${REMOTE_PID_FILE}' ] && kill -0 \$(cat '${REMOTE_PID_FILE}') 2>/dev/null; then \
            kill \$(cat '${REMOTE_PID_FILE}') || true; \
            sleep 2; \
        fi && \
        nohup '${REMOTE_BIN_DIR}/vault' server -dev -dev-root-token-id=root \
            > '${REMOTE_LOG_DIR}/vault-dev.log' 2>&1 < /dev/null & \
        echo \$! > '${REMOTE_PID_FILE}'"

    echo "Waiting for Vault to start..."
    sleep 5
else
    echo "Checking whether Vault is already running on remote host..."
    if ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" \
        "curl -s -o /dev/null http://127.0.0.1:8200/v1/sys/health"; then
        echo "Vault is already running, leaving it as is."
    else
        echo "Vault is not running, starting it with the existing remote binary..."
        ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "\
            test -x '${REMOTE_BIN_DIR}/vault' || { echo 'Error: ${REMOTE_BIN_DIR}/vault not found; run a full deploy first'; exit 1; }; \
            chmod +x '${REMOTE_DIR}'/*.sh; \
            nohup '${REMOTE_BIN_DIR}/vault' server -dev -dev-root-token-id=root \
                > '${REMOTE_LOG_DIR}/vault-dev.log' 2>&1 < /dev/null & \
            echo \$! > '${REMOTE_PID_FILE}'"

        echo "Waiting for Vault to start..."
        sleep 5
    fi
fi

echo "Running trusted profile setup on remote host..."
ssh "${SSH_OPTS[@]}" "${REMOTE_HOST}" "\
    cd '${REMOTE_DIR}' && \
    . '${REMOTE_ENV_FILE}' && \
    ./demo-trusted-profile-setup.sh"

cat <<EOF

Deployment complete.

Remote paths:
  App dir: ${REMOTE_DIR}
  Vault binary: ${REMOTE_BIN_DIR}/vault
  Vault log: ${REMOTE_LOG_DIR}/vault-dev.log
  Env file: ${REMOTE_ENV_FILE}

Useful commands:
  ssh -i ${SSH_KEY} ${REMOTE_HOST}
  ssh -i ${SSH_KEY} ${REMOTE_HOST} 'tail -f ${REMOTE_LOG_DIR}/vault-dev.log'
  ssh -i ${SSH_KEY} ${REMOTE_HOST} 'cd ${REMOTE_DIR} && . ./vault.env && ./bin/vault login -method=ibmcloud role=my-service-writer-role type=trusted_profile'
EOF

# Made with Bob

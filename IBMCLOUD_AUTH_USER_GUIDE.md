# IBM Cloud IAM Authentication - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Getting Started](#getting-started)
4. [Authentication with API Keys](#authentication-with-api-keys)
5. [Authentication with Trusted Profiles](#authentication-with-trusted-profiles)
6. [Using Vault Agent](#using-vault-agent)
7. [Common Use Cases](#common-use-cases)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)
10. [FAQ](#faq)

---

## Introduction

The IBM Cloud IAM authentication method allows you to authenticate to Vault using your IBM Cloud credentials. This method supports two types of authentication:

- **API Key Authentication** - Use IBM Cloud API keys for service IDs or user accounts
- **Trusted Profile Authentication** - Use IBM Cloud Trusted Profiles for compute resources (VPC instances, Kubernetes clusters, etc.)

### When to Use This Method

✅ **Use API Key Authentication when:**
- You have an IBM Cloud service ID or user account
- You need to authenticate from any location (on-premises, other clouds, local machine)
- You want to use long-lived credentials

✅ **Use Trusted Profile Authentication when:**
- You're running on IBM Cloud compute resources (VPC instances, IKS clusters)
- You want automatic, credential-free authentication
- You need short-lived, automatically rotating credentials

---

## Prerequisites

### For All Users

- Access to a Vault server with the IBM Cloud auth method enabled
- Vault CLI installed ([Download](https://www.vaultproject.io/downloads))
- Basic understanding of Vault concepts (tokens, policies, roles)

### For API Key Authentication

- An IBM Cloud account
- An API key for a service ID or user account
- The account ID where your API key belongs

**To create an API key:**
1. Log in to [IBM Cloud Console](https://cloud.ibm.com)
2. Go to **Manage** → **Access (IAM)** → **API keys**
3. Click **Create an IBM Cloud API key**
4. Give it a name and description
5. Copy and save the API key securely (you won't be able to see it again)

### For Trusted Profile Authentication

- A VPC instance or Kubernetes cluster in IBM Cloud
- A Trusted Profile configured with appropriate compute resource access
- The Trusted Profile ID

**To create a Trusted Profile:**
1. Log in to [IBM Cloud Console](https://cloud.ibm.com)
2. Go to **Manage** → **Access (IAM)** → **Trusted profiles**
3. Click **Create profile**
4. Add compute resources (VPC instances, IKS clusters, etc.)
5. Note the Profile ID for configuration

---

## Getting Started

### Step 1: Verify Vault Access

First, ensure you can connect to your Vault server:

```bash
export VAULT_ADDR='https://vault.example.com:8200'
vault status
```

### Step 2: Check if IBM Cloud Auth is Enabled

```bash
vault auth list
```

Look for `ibmcloud/` in the output. If you don't see it, ask your Vault administrator to enable it:

```bash
# Administrator command
vault auth enable ibmcloud
```

### Step 3: Understand Your Role

Ask your Vault administrator which role you should use. Roles define:
- What type of authentication you can use (API key or Trusted Profile)
- Which IBM Cloud identities are allowed
- What Vault policies (permissions) you'll receive

---

## Administrator Guide: Creating Roles

**Note:** This section is for Vault administrators. If you're a user, skip to [Authentication with API Keys](#authentication-with-api-keys).

### Understanding Roles

Roles are the core configuration that determines:
1. **Who can authenticate** - Which IBM Cloud identities are allowed
2. **How they authenticate** - API key or Trusted Profile
3. **What they can access** - Which Vault policies are granted

### Creating an API Key Role

API Key roles allow authentication using IBM Cloud API keys from service IDs or user accounts.

**Basic API Key Role:**
```bash
vault write auth/ibmcloud/role/my-service-role \
    type=apikey \
    bound_account_id=abc123def456 \
    token_policies=my-policy \
    token_ttl=1h \
    token_max_ttl=24h
```

**Parameters:**
- `type` (required) - Must be "apikey"
- `bound_account_id` (required) - IBM Cloud account ID that API keys must belong to
- `bound_service_ids` (optional) - List of specific service IDs allowed (comma-separated)
- `bound_user_ids` (optional) - List of specific user IDs allowed (comma-separated)
- `bound_access_group_ids` (optional) - List of IBM Cloud IAM access group IDs allowed (comma-separated)
- `token_policies` (required) - Vault policies to attach to generated tokens
- `token_ttl` (optional) - Default token TTL (e.g., "1h", "30m")
- `token_max_ttl` (optional) - Maximum token TTL
- `token_bound_cidrs` (optional) - CIDR blocks that can use the token

**Example: Role for specific service IDs:**
```bash
vault write auth/ibmcloud/role/cicd-role \
    type=apikey \
    bound_account_id=abc123def456 \
    bound_service_ids=ServiceId-12345678-1234-1234-1234-123456789012,ServiceId-87654321-4321-4321-4321-210987654321 \
    token_policies=cicd-policy,secrets-read \
    token_ttl=2h \
    token_max_ttl=8h
```

**Example: Role for development team:**
```bash
vault write auth/ibmcloud/role/developer-role \
    type=apikey \
    bound_account_id=abc123def456 \
    token_policies=dev-policy,read-only \
    token_ttl=8h \
    token_max_ttl=24h
```

**Example: Role for access group members:**
```bash
vault write auth/ibmcloud/role/team-access-role \
    type=apikey \
    bound_account_id=abc123def456 \
    bound_access_group_ids=AccessGroupId-12345678-1234-1234-1234-123456789012 \
    token_policies=team-policy,shared-secrets \
    token_ttl=4h \
    token_max_ttl=12h
```

### Creating a Trusted Profile Role

Trusted Profile roles allow authentication from IBM Cloud compute resources (VPC instances, Kubernetes clusters).

**Basic Trusted Profile Role:**
```bash
vault write auth/ibmcloud/role/vpc-app-role \
    type=trusted_profile \
    bound_trusted_profile_id=Profile-12345678-1234-1234-1234-123456789012 \
    token_policies=app-policy \
    token_ttl=1h \
    token_max_ttl=4h
```

**Parameters:**
- `type` (required) - Must be "trusted_profile"
- `bound_trusted_profile_id` (required) - Trusted Profile ID that must be used
- `bound_compute_resource_crn` (optional) - CRN patterns for allowed compute resources
- `bound_compute_resource_type` (optional) - Resource types allowed (e.g., "vsi", "iks")
- `token_policies` (required) - Vault policies to attach to generated tokens
- `token_ttl` (optional) - Default token TTL
- `token_max_ttl` (optional) - Maximum token TTL

**Example: Role for specific VPC instances:**
```bash
vault write auth/ibmcloud/role/production-vpc-role \
    type=trusted_profile \
    bound_trusted_profile_id=Profile-12345678-1234-1234-1234-123456789012 \
    bound_compute_resource_crn=crn:v1:bluemix:public:is:us-south-1:a/abc123::instance:* \
    token_policies=production-policy,database-access \
    token_ttl=30m \
    token_max_ttl=2h
```

**Example: Role for Kubernetes workloads:**
```bash
vault write auth/ibmcloud/role/k8s-app-role \
    type=trusted_profile \
    bound_trusted_profile_id=Profile-87654321-4321-4321-4321-210987654321 \
    bound_compute_resource_type=iks \
    token_policies=k8s-policy,secrets-read \
    token_ttl=15m \
    token_max_ttl=1h
```

### Managing Roles

**List all roles:**
```bash
vault list auth/ibmcloud/role
```

**Read a role configuration:**
```bash
vault read auth/ibmcloud/role/my-service-role
```

**Update a role:**
```bash
vault write auth/ibmcloud/role/my-service-role \
    token_ttl=2h \
    token_policies=updated-policy
```

**Delete a role:**
```bash
vault delete auth/ibmcloud/role/my-service-role
```

### Role Design Best Practices

1. **Use descriptive role names** - Include environment and purpose (e.g., `prod-api-role`, `dev-vpc-role`)

2. **Principle of least privilege** - Grant only the minimum policies needed
   ```bash
   # Good: Specific policies
   token_policies=app-secrets-read,database-creds
   
   # Avoid: Overly broad policies
   token_policies=admin,root
   ```

3. **Separate roles by environment**
   ```bash
   # Development
   vault write auth/ibmcloud/role/dev-role ...
   
   # Staging
   vault write auth/ibmcloud/role/staging-role ...
   
   # Production
   vault write auth/ibmcloud/role/prod-role ...
   ```

4. **Use appropriate TTLs**
   - Short-lived for production (15m-1h)
   - Longer for development (4h-8h)
   - Consider token renewal needs

5. **Restrict by identity when possible**
   ```bash
   # Restrict to specific service IDs
   bound_service_ids=ServiceId-xxx,ServiceId-yyy
   
   # Restrict to specific compute resources
   bound_compute_resource_crn=crn:v1:bluemix:public:is:us-south-1:a/abc123::instance:*
   ```

### Common Role Patterns

**Pattern 1: CI/CD Pipeline Role**
```bash
vault write auth/ibmcloud/role/cicd-pipeline \
    type=apikey \
    bound_account_id=abc123def456 \
    bound_service_ids=ServiceId-cicd-12345 \
    token_policies=cicd-deploy,secrets-read \
    token_ttl=30m \
    token_max_ttl=2h \
    token_num_uses=10
```

**Pattern 2: Application on VPC Role**
```bash
vault write auth/ibmcloud/role/app-vpc-instance \
    type=trusted_profile \
    bound_trusted_profile_id=Profile-app-12345 \
    bound_compute_resource_type=vsi \
    token_policies=app-secrets,database-dynamic-creds \
    token_ttl=1h \
    token_max_ttl=4h
```

**Pattern 3: Developer Access Role**
```bash
vault write auth/ibmcloud/role/developer-access \
    type=apikey \
    bound_account_id=abc123def456 \
    token_policies=dev-read,dev-write \
    token_ttl=8h \
    token_max_ttl=24h \
    token_bound_cidrs=10.0.0.0/8,172.16.0.0/12
```

**Pattern 4: Kubernetes Workload Role**
```bash
vault write auth/ibmcloud/role/k8s-workload \
    type=trusted_profile \
    bound_trusted_profile_id=Profile-k8s-12345 \
    bound_compute_resource_type=iks \
    token_policies=k8s-app-secrets \
    token_ttl=15m \
    token_max_ttl=1h \
    token_period=15m
```

---

## Authentication with API Keys

### Quick Start

The simplest way to authenticate with an API key:

```bash
vault login -method=ibmcloud \
    role=my-role \
    type=apikey \
    apikey=YOUR_API_KEY
```

### Step-by-Step Guide

#### 1. Gather Required Information

You need:
- **Role name** - Provided by your Vault administrator
- **API key** - Your IBM Cloud API key
- **Account ID** - Your IBM Cloud account ID (optional, for verification)

To find your account ID:
```bash
ibmcloud account show
```

#### 2. Authenticate

```bash
vault login -method=ibmcloud \
    role=my-service-role \
    type=apikey \
    apikey=YOUR_API_KEY_HERE
```

**Example output:**
```
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.CAESI...
token_accessor       hmac-sha256:...
token_duration       1h
token_renewable      true
token_policies       ["default" "my-policy"]
identity_policies    []
policies             ["default" "my-policy"]
token_meta_account_id    abc123def456
token_meta_auth_type     apikey
token_meta_iam_id        IBMid-123456
```

#### 3. Verify Authentication

```bash
vault token lookup
```

### Using Environment Variables

For convenience, you can set environment variables:

```bash
export VAULT_ADDR='https://vault.example.com:8200'
export IBMCLOUD_API_KEY='your-api-key'

vault login -method=ibmcloud \
    role=my-role \
    type=apikey \
    apikey=$IBMCLOUD_API_KEY
```

### Scripting Authentication

For automation, save the token to a file:

```bash
vault login -method=ibmcloud \
    role=my-role \
    type=apikey \
    apikey=$IBMCLOUD_API_KEY \
    -token-only > ~/.vault-token

# Now use Vault commands
vault kv get secret/myapp/config
```

---

## Authentication with Trusted Profiles

### Quick Start

From a VPC instance with a Trusted Profile attached:

```bash
vault login -method=ibmcloud \
    role=my-compute-role \
    type=trusted_profile
```

That's it! The authentication will automatically fetch the compute resource token from the VPC metadata service.

### Step-by-Step Guide

#### 1. Verify You're on a Compute Resource

Check if the metadata service is available:

```bash
curl -X PUT "http://169.254.169.254/instance_identity/v1/token" \
    -H "Metadata-Flavor: ibm" \
    -d '{"expires_in": 3600}'
```

If this returns a token, you're ready to use Trusted Profile authentication.

#### 2. Gather Required Information

You need:
- **Role name** - Provided by your Vault administrator
- **Trusted Profile ID** - Usually configured in the role, but can be overridden

To find your instance's Trusted Profile:
```bash
curl -X GET "http://169.254.169.254/instance_identity/v1/token" \
    -H "Metadata-Flavor: ibm" | jq -r '.profile_id'
```

#### 3. Authenticate (Automatic)

```bash
vault login -method=ibmcloud \
    role=my-compute-role \
    type=trusted_profile
```

The CR token is automatically fetched from the metadata service.

#### 4. Authenticate (Manual CR Token)

If you need to provide the CR token manually:

```bash
# Get CR token
CR_TOKEN=$(curl -X PUT "http://169.254.169.254/instance_identity/v1/token" \
    -H "Metadata-Flavor: ibm" \
    -d '{"expires_in": 3600}' | jq -r '.access_token')

# Authenticate
vault login -method=ibmcloud \
    role=my-compute-role \
    type=trusted_profile \
    cr_token=$CR_TOKEN
```

### Override Trusted Profile ID

If you need to use a different Trusted Profile than the one attached to your instance:

```bash
vault login -method=ibmcloud \
    role=my-compute-role \
    type=trusted_profile \
    trusted_profile_id=Profile-12345678-1234-1234-1234-123456789012
```

---

## Using Vault Agent

Vault Agent can automatically authenticate and keep your token fresh. This is ideal for applications that need continuous access to Vault.

### API Key Configuration

Create a configuration file `agent-config.hcl`:

```hcl
# Vault server address
vault {
  address = "https://vault.example.com:8200"
}

# Auto-auth configuration
auto_auth {
  method {
    type = "ibmcloud"
    
    config = {
      role   = "my-service-role"
      type   = "apikey"
      apikey = "YOUR_API_KEY_HERE"
    }
  }
  
  # Where to write the token
  sink {
    type = "file"
    config = {
      path = "/tmp/vault-token"
    }
  }
}

# Optional: Template for secrets
template {
  source      = "/etc/myapp/config.tmpl"
  destination = "/etc/myapp/config.json"
}
```

**Using environment variables for the API key:**

```hcl
auto_auth {
  method {
    type = "ibmcloud"
    
    config = {
      role   = "my-service-role"
      type   = "apikey"
      apikey = env("IBMCLOUD_API_KEY")
    }
  }
  
  sink {
    type = "file"
    config = {
      path = "/tmp/vault-token"
    }
  }
}
```

### Trusted Profile Configuration

For VPC instances or Kubernetes pods:

```hcl
vault {
  address = "https://vault.example.com:8200"
}

auto_auth {
  method {
    type = "ibmcloud"
    
    config = {
      role = "my-compute-role"
      type = "trusted_profile"
      # CR token is automatically fetched
      # Credentials are automatically refreshed every 60 seconds
    }
  }
  
  sink {
    type = "file"
    config = {
      path = "/tmp/vault-token"
    }
  }
}
```

### Running Vault Agent

```bash
# Start the agent
vault agent -config=agent-config.hcl

# Or run in background
vault agent -config=agent-config.hcl &

# Your application can now read the token
cat /tmp/vault-token
```

### Vault Agent with Templates

Automatically render secrets into configuration files:

```hcl
vault {
  address = "https://vault.example.com:8200"
}

auto_auth {
  method {
    type = "ibmcloud"
    config = {
      role = "my-app-role"
      type = "apikey"
      apikey = env("IBMCLOUD_API_KEY")
    }
  }
  
  sink {
    type = "file"
    config = {
      path = "/tmp/vault-token"
    }
  }
}

# Render database credentials
template {
  source      = "/etc/myapp/db-config.tmpl"
  destination = "/etc/myapp/db-config.json"
  command     = "systemctl reload myapp"
}
```

**Template file** (`/etc/myapp/db-config.tmpl`):
```json
{{- with secret "database/creds/myapp" }}
{
  "host": "db.example.com",
  "username": "{{ .Data.username }}",
  "password": "{{ .Data.password }}"
}
{{- end }}
```

---

## Common Use Cases

### Use Case 1: CI/CD Pipeline Authentication

**Scenario:** Authenticate from a CI/CD pipeline using a service ID API key.

```bash
#!/bin/bash
# In your CI/CD script

# Authenticate to Vault
vault login -method=ibmcloud \
    role=cicd-role \
    type=apikey \
    apikey=$IBMCLOUD_API_KEY \
    -token-only > /tmp/vault-token

export VAULT_TOKEN=$(cat /tmp/vault-token)

# Fetch secrets
DB_PASSWORD=$(vault kv get -field=password secret/myapp/database)

# Use secrets in deployment
kubectl create secret generic db-creds \
    --from-literal=password=$DB_PASSWORD
```

### Use Case 2: Application on VPC Instance

**Scenario:** Application running on a VPC instance needs to access secrets.

**Setup (one-time):**
1. Attach Trusted Profile to your VPC instance
2. Configure Vault Agent on the instance

**agent-config.hcl:**
```hcl
vault {
  address = "https://vault.example.com:8200"
}

auto_auth {
  method {
    type = "ibmcloud"
    config = {
      role = "vpc-app-role"
      type = "trusted_profile"
    }
  }
  
  sink {
    type = "file"
    config = {
      path = "/var/run/vault/token"
      mode = 0600
    }
  }
}

template {
  source      = "/etc/myapp/secrets.tmpl"
  destination = "/etc/myapp/secrets.env"
  command     = "systemctl reload myapp"
}
```

**Start agent as a service:**
```bash
sudo systemctl enable vault-agent
sudo systemctl start vault-agent
```

### Use Case 3: Kubernetes Workload

**Scenario:** Kubernetes pod needs to authenticate using Trusted Profile.

**Deployment with Vault Agent sidecar:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      # Main application container
      - name: myapp
        image: myapp:latest
        volumeMounts:
        - name: vault-token
          mountPath: /vault
          readOnly: true
        env:
        - name: VAULT_TOKEN
          value: /vault/token
      
      # Vault Agent sidecar
      - name: vault-agent
        image: hashicorp/vault:latest
        args:
        - agent
        - -config=/vault/config/agent-config.hcl
        volumeMounts:
        - name: vault-config
          mountPath: /vault/config
        - name: vault-token
          mountPath: /vault
      
      volumes:
      - name: vault-config
        configMap:
          name: vault-agent-config
      - name: vault-token
        emptyDir:
          medium: Memory
```

**ConfigMap:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-agent-config
data:
  agent-config.hcl: |
    vault {
      address = "https://vault.example.com:8200"
    }
    
    auto_auth {
      method {
        type = "ibmcloud"
        config = {
          role = "k8s-app-role"
          type = "trusted_profile"
        }
      }
      
      sink {
        type = "file"
        config = {
          path = "/vault/token"
        }
      }
    }
```

### Use Case 4: Local Development

**Scenario:** Developer needs to access Vault from their local machine.

```bash
# Set up environment
export VAULT_ADDR='https://vault.example.com:8200'
export IBMCLOUD_API_KEY='your-dev-api-key'

# Create a login script
cat > vault-login.sh << 'EOF'
#!/bin/bash
vault login -method=ibmcloud \
    role=developer-role \
    type=apikey \
    apikey=$IBMCLOUD_API_KEY
EOF

chmod +x vault-login.sh

# Login
./vault-login.sh

# Now use Vault
vault kv get secret/myapp/dev-config
```

---

## Troubleshooting

### Problem: "role not found"

**Error message:**
```
Error authenticating: Error making API request.
URL: PUT https://vault.example.com:8200/v1/auth/ibmcloud/login
Code: 400. Errors:
* role not found
```

**Solution:**
- Verify the role name is correct
- Ask your Vault administrator if the role exists
- Check if you have the correct mount path (default is `ibmcloud`)

### Problem: "account ID does not match role binding"

**Error message:**
```
Error authenticating: Error making API request.
Code: 403. Errors:
* authentication failed: account ID does not match role binding
```

**Solution:**
- Verify your API key belongs to the correct IBM Cloud account
- Check with your Vault administrator what account ID the role expects
- Ensure you're using the correct role for your account

### Problem: "VPC metadata service unavailable"

**Error message:**
```
Error authenticating: Error making API request.
Code: 500. Errors:
* VPC metadata service unavailable
```

**Solution:**
- Verify you're running on a VPC instance
- Check network connectivity: `curl http://169.254.169.254`
- Ensure the instance has a Trusted Profile attached
- Verify the metadata service is enabled on your VPC

### Problem: "trusted profile ID does not match role binding"

**Error message:**
```
Error authenticating: Error making API request.
Code: 403. Errors:
* authentication failed: trusted profile ID does not match role binding
```

**Solution:**
- Verify your instance has the correct Trusted Profile attached
- Check the Trusted Profile ID: `curl http://169.254.169.254/instance_identity/v1/token | jq -r '.profile_id'`
- Confirm with your Vault administrator which Trusted Profile the role expects

### Problem: "invalid API key"

**Error message:**
```
Error authenticating: Error making API request.
Code: 401. Errors:
* failed to exchange credentials for IAM token: invalid API key
```

**Solution:**
- Verify your API key is correct (no extra spaces or characters)
- Check if the API key has been deleted or disabled in IBM Cloud
- Ensure the API key hasn't expired (if it has an expiration date)
- Try creating a new API key

### Problem: Token expires too quickly

**Symptom:** Your Vault token expires before you finish your work.

**Solution:**
- Ask your Vault administrator to increase the `token_ttl` on your role
- Use Vault Agent to automatically renew your token
- Use `vault token renew` to manually renew before expiration

### Problem: Vault Agent not refreshing credentials

**Symptom:** Vault Agent stops working after the initial authentication.

**Solution:**
- Check Vault Agent logs: `journalctl -u vault-agent -f`
- Verify the metadata service is accessible
- Ensure the `credential_poll_interval` is set appropriately
- Restart Vault Agent: `systemctl restart vault-agent`

---

## Best Practices

### Security Best Practices

1. **Never commit API keys to version control**
   ```bash
   # Use environment variables
   export IBMCLOUD_API_KEY='your-key'
   
   # Or use a secrets manager
   vault kv get -field=apikey secret/ibmcloud/keys
   ```

2. **Use service IDs instead of user API keys**
   - Service IDs are designed for applications
   - Easier to manage and rotate
   - Better audit trail

3. **Rotate API keys regularly**
   ```bash
   # Create new API key
   ibmcloud iam service-api-key-create new-key ServiceId-xxx
   
   # Update applications
   # Delete old key
   ibmcloud iam service-api-key-delete old-key ServiceId-xxx
   ```

4. **Use Trusted Profiles when possible**
   - No credentials to manage
   - Automatic rotation
   - Better security posture

5. **Limit token TTL**
   - Request the minimum TTL needed
   - Use Vault Agent for automatic renewal
   - Don't use long-lived tokens unnecessarily

### Operational Best Practices

1. **Use Vault Agent for applications**
   - Automatic authentication
   - Automatic token renewal
   - Template rendering for secrets

2. **Monitor token expiration**
   ```bash
   # Check token TTL
   vault token lookup -format=json | jq -r '.data.ttl'
   ```

3. **Use appropriate roles**
   - Development role for dev environment
   - Production role for prod environment
   - Separate roles for different applications

4. **Log authentication events**
   - Enable audit logging in Vault
   - Monitor for failed authentication attempts
   - Set up alerts for suspicious activity

5. **Test in non-production first**
   - Verify authentication works in dev/staging
   - Test token renewal and expiration
   - Validate policy permissions

---

## FAQ

### Q: Can I use the same API key for multiple applications?

**A:** While technically possible, it's not recommended. Each application should have its own service ID and API key for better security and audit trails.

### Q: How long do tokens last?

**A:** Token duration is configured by your Vault administrator in the role. Typical values are 1 hour to 24 hours. You can check your token's TTL with:
```bash
vault token lookup
```

### Q: Can I renew my token?

**A:** Yes, if the token is renewable:
```bash
vault token renew
```

Or use Vault Agent to automatically renew tokens.

### Q: What happens if my API key is compromised?

**A:** Immediately:
1. Delete the API key in IBM Cloud Console
2. Revoke any active Vault tokens using that key (ask your Vault admin)
3. Create a new API key
4. Update your applications with the new key

### Q: Can I use this from outside IBM Cloud?

**A:** Yes, with API key authentication. Trusted Profile authentication only works from IBM Cloud compute resources.

### Q: How do I know which role to use?

**A:** Ask your Vault administrator. They will provide:
- Role name
- Authentication type (apikey or trusted_profile)
- Any specific requirements

### Q: Can I have multiple roles?

**A:** Yes, you can authenticate with different roles for different purposes. Each authentication creates a separate token.

### Q: What policies will I get?

**A:** Policies are configured in the role by your Vault administrator. You can see your policies with:
```bash
vault token lookup
```

### Q: How do I test if my authentication works?

**A:** Try a simple authentication:
```bash
vault login -method=ibmcloud role=my-role type=apikey apikey=$IBMCLOUD_API_KEY
vault token lookup
```

### Q: Can I use this with Terraform?

**A:** Yes! Use the Vault provider:
```hcl
provider "vault" {
  address = "https://vault.example.com:8200"
  
  auth_login {
    path = "auth/ibmcloud/login"
    
    parameters = {
      role   = "terraform-role"
      type   = "apikey"
      apikey = var.ibmcloud_api_key
    }
  }
}
```

---

## Getting Help

### Documentation
- [IBM Cloud IAM Documentation](https://cloud.ibm.com/docs/account?topic=account-iamoverview)
- [Vault Documentation](https://www.vaultproject.io/docs)
- [Trusted Profiles Guide](https://cloud.ibm.com/docs/account?topic=account-create-trusted-profile)

### Support
- Contact your Vault administrator for role and configuration issues
- IBM Cloud Support for IBM Cloud IAM issues
- HashiCorp Support for Vault issues

### Quick Reference

**API Key Authentication:**
```bash
vault login -method=ibmcloud role=ROLE type=apikey apikey=KEY
```

**Trusted Profile Authentication:**
```bash
vault login -method=ibmcloud role=ROLE type=trusted_profile
```

**Check Token:**
```bash
vault token lookup
```

**Renew Token:**
```bash
vault token renew
```

**Revoke Token:**
```bash
vault token revoke -self
```

---

## Appendix: Complete Examples

### Example 1: Simple API Key Script

```bash
#!/bin/bash
set -e

# Configuration
VAULT_ADDR="https://vault.example.com:8200"
VAULT_ROLE="my-app-role"
IBMCLOUD_API_KEY="your-api-key"

# Authenticate
echo "Authenticating to Vault..."
export VAULT_TOKEN=$(vault login -method=ibmcloud \
    -address=$VAULT_ADDR \
    role=$VAULT_ROLE \
    type=apikey \
    apikey=$IBMCLOUD_API_KEY \
    -token-only)

# Fetch secrets
echo "Fetching secrets..."
DB_HOST=$(vault kv get -field=host secret/myapp/database)
DB_USER=$(vault kv get -field=username secret/myapp/database)
DB_PASS=$(vault kv get -field=password secret/myapp/database)

# Use secrets
echo "Connecting to database..."
psql -h $DB_HOST -U $DB_USER -d myapp

# Cleanup
vault token revoke -self
```

### Example 2: Systemd Service with Vault Agent

**`/etc/systemd/system/vault-agent.service`:**
```ini
[Unit]
Description=Vault Agent
Requires=network-online.target
After=network-online.target

[Service]
Type=simple
User=vault
Group=vault
ExecStart=/usr/local/bin/vault agent -config=/etc/vault-agent/config.hcl
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**`/etc/vault-agent/config.hcl`:**
```hcl
vault {
  address = "https://vault.example.com:8200"
}

auto_auth {
  method {
    type = "ibmcloud"
    config = {
      role = "vpc-app-role"
      type = "trusted_profile"
    }
  }
  
  sink {
    type = "file"
    config = {
      path = "/var/run/vault/token"
      mode = 0600
    }
  }
}
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable vault-agent
sudo systemctl start vault-agent
sudo systemctl status vault-agent
```

---

**End of User Guide**

For technical implementation details, see:
- `IBMCLOUD_AUTH_IMPLEMENTATION_PLAN.md`
- `IBMCLOUD_AUTH_TECHNICAL_SPEC.md`
- `IBMCLOUD_AUTH_SUMMARY.md`
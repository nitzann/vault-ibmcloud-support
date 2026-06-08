# IBM Cloud IAM Authentication - Technical Specification

## 1. Authentication Types

### 1.1 API Key Authentication

**Flow:**
1. Client provides IBM Cloud API key
2. Backend exchanges API key for IAM access token using IAM Identity API
3. Backend validates token and extracts identity information (account_id, service_id, user_id)
4. Backend matches identity against role bindings
5. Backend issues Vault token if authorized

**IBM Cloud API Endpoint:**
```
POST https://iam.cloud.ibm.com/identity/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey={API_KEY}
```

**Response:**
```json
{
  "access_token": "eyJraWQiOiI...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "expiration": 1234567890,
  "scope": "ibm openid"
}
```

**Token Claims (JWT):**
```json
{
  "iam_id": "IBMid-123456",
  "id": "IBMid-123456",
  "realmid": "IBMid",
  "identifier": "123456",
  "given_name": "John",
  "family_name": "Doe",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "sub": "john.doe@example.com",
  "account": {
    "valid": true,
    "bss": "abc123def456"
  },
  "iat": 1234567890,
  "exp": 1234571490,
  "iss": "https://iam.cloud.ibm.com/identity",
  "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
  "scope": "ibm openid",
  "client_id": "default",
  "acr": 1,
  "amr": ["pwd"]
}
```

### 1.2 Trusted Profile Authentication

**Flow:**
1. Client obtains compute resource (CR) token from VPC metadata service (or provides manually)
2. Client provides CR token and optionally trusted profile ID
3. Backend exchanges CR token for IAM access token using IAM Identity API
4. Backend validates token and extracts trusted profile information
5. Backend matches identity against role bindings (trusted_profile_id, compute resource CRN)
6. Backend issues Vault token if authorized

**VPC Metadata Service Endpoint (CR Token):**
```
PUT http://169.254.169.254/instance_identity/v1/token
Metadata-Flavor: ibm

{
  "expires_in": 3600
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIwMjQwMTE1MTYzMCJ9...",
  "created_at": "2024-01-15T10:30:00Z",
  "expires_at": "2024-01-15T11:30:00Z",
  "expires_in": 3600
}
```

**CR Token Claims:**
```json
{
  "iat": 1234567890,
  "exp": 1234571490,
  "sub": "crn:v1:bluemix:public:is:us-south-1:a/abc123::instance:0716_12345678-1234-1234-1234-123456789012",
  "iss": "https://iam.cloud.ibm.com/identity",
  "account": "abc123",
  "instance_id": "0716_12345678-1234-1234-1234-123456789012",
  "profile_id": "Profile-12345678-1234-1234-1234-123456789012",
  "profile_name": "my-trusted-profile"
}
```

**IAM Token Exchange Endpoint:**
```
POST https://iam.cloud.ibm.com/identity/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ibm:params:oauth:grant-type:cr-token&cr_token={CR_TOKEN}&profile_id={PROFILE_ID}
```

**Response:** Same format as API key authentication

**IAM Token Claims (for Trusted Profile):**
```json
{
  "iam_id": "iam-Profile-12345678-1234-1234-1234-123456789012",
  "id": "iam-Profile-12345678-1234-1234-1234-123456789012",
  "realmid": "iam",
  "identifier": "Profile-12345678-1234-1234-1234-123456789012",
  "name": "my-trusted-profile",
  "sub": "crn:v1:bluemix:public:is:us-south-1:a/abc123::instance:0716_12345678-1234-1234-1234-123456789012",
  "sub_type": "cr",
  "account": {
    "valid": true,
    "bss": "abc123"
  },
  "iat": 1234567890,
  "exp": 1234571490,
  "iss": "https://iam.cloud.ibm.com/identity",
  "grant_type": "urn:ibm:params:oauth:grant-type:cr-token",
  "scope": "ibm openid",
  "client_id": "default",
  "acr": 1,
  "amr": ["cr-token"]
}
```

## 2. Role Binding Logic

### 2.1 API Key Role Binding

**Required Match:**
- `bound_account_id` MUST match token's `account.bss` claim

**Optional Matches (if specified):**
- `bound_service_ids` - If specified, token's `iam_id` must match one of the service IDs
- `bound_user_ids` - If specified, token's `iam_id` must match one of the user IDs
- `bound_access_group_ids` - If specified, token must contain access group membership that matches one of the access group IDs

**Validation Logic:**
```go
func validateAPIKeyBinding(token *IAMToken, role *Role) error {
    // Check account ID (required)
    if token.Account.BSS != role.BoundAccountID {
        return fmt.Errorf("account ID mismatch")
    }
    
    // Check service IDs (if specified)
    if len(role.BoundServiceIDs) > 0 {
        if !contains(role.BoundServiceIDs, token.IAMID) {
            return fmt.Errorf("service ID not authorized")
        }
    }
    
    // Check user IDs (if specified)
    if len(role.BoundUserIDs) > 0 {
        if !contains(role.BoundUserIDs, token.IAMID) {
            return fmt.Errorf("user ID not authorized")
        }
    }
    
    // Check access group IDs (if specified)
    if len(role.BoundAccessGroupIDs) > 0 {
        if !hasAccessGroupMembership(token, role.BoundAccessGroupIDs) {
            return fmt.Errorf("access group membership not authorized")
        }
    }
    
    return nil
}
```

### 2.2 Trusted Profile Role Binding

**Required Match:**
- `bound_trusted_profile_id` MUST match token's `identifier` claim (the profile ID)

**Optional Matches (if specified):**
- `bound_compute_resource_crn` - If specified, token's `sub` claim must match one of the CRN patterns (supports wildcards)
- `bound_compute_resource_type` - If specified, compute resource type extracted from CRN must match

**CRN Format:**
```
crn:version:cname:ctype:service-name:location:scope:service-instance:resource-type:resource
```

**Example CRN:**
```
crn:v1:bluemix:public:is:us-south-1:a/abc123::instance:0716_12345678-1234-1234-1234-123456789012
```

**Validation Logic:**
```go
func validateTrustedProfileBinding(token *IAMToken, role *Role) error {
    // Check trusted profile ID (required)
    if token.Identifier != role.BoundTrustedProfileID {
        return fmt.Errorf("trusted profile ID mismatch")
    }
    
    // Check compute resource CRN patterns (if specified)
    if len(role.BoundComputeResourceCRN) > 0 {
        matched := false
        for _, pattern := range role.BoundComputeResourceCRN {
            if matchCRNPattern(token.Sub, pattern) {
                matched = true
                break
            }
        }
        if !matched {
            return fmt.Errorf("compute resource CRN not authorized")
        }
    }
    
    // Check compute resource type (if specified)
    if len(role.BoundComputeResourceType) > 0 {
        resourceType := extractResourceTypeFromCRN(token.Sub)
        if !contains(role.BoundComputeResourceType, resourceType) {
            return fmt.Errorf("compute resource type not authorized")
        }
    }
    
    return nil
}

func matchCRNPattern(crn, pattern string) bool {
    // Support wildcards in CRN patterns
    // Example: crn:v1:bluemix:public:is:*:a/abc123::instance:*
    // Matches any region and any instance ID for account abc123
    
    // Convert pattern to regex
    regex := strings.ReplaceAll(pattern, "*", ".*")
    regex = "^" + regex + "$"
    
    matched, _ := regexp.MatchString(regex, crn)
    return matched
}

func extractResourceTypeFromCRN(crn string) string {
    // CRN format: crn:version:cname:ctype:service-name:location:scope:service-instance:resource-type:resource
    parts := strings.Split(crn, ":")
    if len(parts) >= 9 {
        return parts[8] // resource-type
    }
    return ""
}
```

## 3. Storage Schema

### 3.1 Configuration Storage

**Path:** `config/ibmcloud`

**Schema:**
```go
type ConfigEntry struct {
    IAMEndpoint      string `json:"iam_endpoint"`
    MetadataEndpoint string `json:"metadata_endpoint"`
    IAMClientTimeout int    `json:"iam_client_timeout"` // seconds
}
```

**Default Values:**
```go
const (
    DefaultIAMEndpoint      = "https://iam.cloud.ibm.com"
    DefaultMetadataEndpoint = "http://169.254.169.254"
    DefaultIAMClientTimeout = 30 // seconds
)
```

### 3.2 Role Storage

**Path:** `role/:name`

**Schema:**
```go
type RoleEntry struct {
    // Common fields
    Type                    string        `json:"type"` // "apikey" or "trusted_profile"
    TokenTTL                time.Duration `json:"token_ttl"`
    TokenMaxTTL             time.Duration `json:"token_max_ttl"`
    TokenPolicies           []string      `json:"token_policies"`
    TokenBoundCIDRs         []string      `json:"token_bound_cidrs"`
    TokenExplicitMaxTTL     time.Duration `json:"token_explicit_max_ttl"`
    TokenNoDefaultPolicy    bool          `json:"token_no_default_policy"`
    TokenNumUses            int           `json:"token_num_uses"`
    TokenPeriod             time.Duration `json:"token_period"`
    TokenType               string        `json:"token_type"`
    
    // API Key specific fields
    BoundAccountID          string        `json:"bound_account_id,omitempty"`
    BoundServiceIDs         []string      `json:"bound_service_ids,omitempty"`
    BoundUserIDs            []string      `json:"bound_user_ids,omitempty"`
    
    // Trusted Profile specific fields
    BoundTrustedProfileID   string        `json:"bound_trusted_profile_id,omitempty"`
    BoundComputeResourceCRN []string      `json:"bound_compute_resource_crn,omitempty"`
    BoundComputeResourceType []string     `json:"bound_compute_resource_type,omitempty"`
}
```

## 4. Error Handling

### 4.1 Error Types

```go
var (
    ErrInvalidAuthType           = errors.New("invalid auth type, must be 'apikey' or 'trusted_profile'")
    ErrMissingAPIKey             = errors.New("api key is required for apikey auth type")
    ErrMissingRole               = errors.New("role is required")
    ErrRoleNotFound              = errors.New("role not found")
    ErrRoleTypeMismatch          = errors.New("role type does not match auth type")
    ErrAccountIDMismatch         = errors.New("account ID does not match role binding")
    ErrServiceIDNotAuthorized    = errors.New("service ID not authorized for this role")
    ErrUserIDNotAuthorized       = errors.New("user ID not authorized for this role")
    ErrTrustedProfileIDMismatch  = errors.New("trusted profile ID does not match role binding")
    ErrComputeResourceNotAuthorized = errors.New("compute resource not authorized for this role")
    ErrIAMTokenExchange          = errors.New("failed to exchange credentials for IAM token")
    ErrIAMTokenValidation        = errors.New("failed to validate IAM token")
    ErrMetadataServiceUnavailable = errors.New("VPC metadata service unavailable")
    ErrCRTokenFetch              = errors.New("failed to fetch CR token from metadata service")
)
```

### 4.2 Error Response Format

```json
{
  "errors": [
    "authentication failed: account ID does not match role binding"
  ]
}
```

## 5. Metadata in Vault Token

### 5.1 API Key Authentication Metadata

```go
metadata := map[string]string{
    "auth_type":    "apikey",
    "account_id":   token.Account.BSS,
    "iam_id":       token.IAMID,
    "identifier":   token.Identifier,
    "email":        token.Email,
    "name":         token.Name,
}
```

### 5.2 Trusted Profile Authentication Metadata

```go
metadata := map[string]string{
    "auth_type":           "trusted_profile",
    "account_id":          token.Account.BSS,
    "trusted_profile_id":  token.Identifier,
    "trusted_profile_name": token.Name,
    "compute_resource_crn": token.Sub,
    "compute_resource_type": extractResourceTypeFromCRN(token.Sub),
}
```

## 6. Vault Agent Credential Refresh

### 6.1 Refresh Strategy

**For API Key:**
- API keys don't expire, but IAM tokens do (typically 1 hour)
- Agent should monitor token expiration and re-authenticate before expiry
- No need to poll for new credentials

**For Trusted Profile:**
- CR tokens expire (configurable, typically 1 hour)
- IAM tokens also expire
- Agent should:
  1. Poll metadata service for new CR tokens before expiry
  2. Re-authenticate with new CR token
  3. Default poll interval: 60 seconds

### 6.2 Credential Refresh Implementation

```go
func (a *ibmcloudMethod) startCredentialRefresh(ctx context.Context) {
    if a.authType != "trusted_profile" {
        return // No refresh needed for API keys
    }
    
    ticker := time.NewTicker(a.credentialPollInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-a.stopCh:
            return
        case <-ticker.C:
            // Fetch new CR token
            newToken, err := a.fetchCRToken(ctx)
            if err != nil {
                a.logger.Warn("failed to fetch new CR token", "error", err)
                continue
            }
            
            // Check if token changed
            a.credLock.Lock()
            if newToken != a.crToken {
                a.crToken = newToken
                a.credLock.Unlock()
                
                // Notify that new credentials are available
                select {
                case a.credsFound <- struct{}{}:
                default:
                }
            } else {
                a.credLock.Unlock()
            }
        }
    }
}
```

## 7. HTTP Client Configuration

### 7.1 Timeouts

```go
const (
    DefaultDialTimeout      = 10 * time.Second
    DefaultRequestTimeout   = 30 * time.Second
    DefaultIdleConnTimeout  = 90 * time.Second
    DefaultMaxIdleConns     = 100
    DefaultMaxIdleConnsPerHost = 10
)

func newHTTPClient(timeout time.Duration) *http.Client {
    return &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            DialContext: (&net.Dialer{
                Timeout: DefaultDialTimeout,
            }).DialContext,
            IdleConnTimeout:     DefaultIdleConnTimeout,
            MaxIdleConns:        DefaultMaxIdleConns,
            MaxIdleConnsPerHost: DefaultMaxIdleConnsPerHost,
            TLSHandshakeTimeout: 10 * time.Second,
        },
    }
}
```

### 7.2 Retry Logic

```go
func (c *IBMCloudIAMClient) exchangeTokenWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
    maxRetries := 3
    backoff := 1 * time.Second
    
    for i := 0; i < maxRetries; i++ {
        resp, err := c.httpClient.Do(req.WithContext(ctx))
        
        if err == nil && resp.StatusCode < 500 {
            return resp, nil
        }
        
        if i < maxRetries-1 {
            time.Sleep(backoff)
            backoff *= 2
        }
    }
    
    return nil, fmt.Errorf("max retries exceeded")
}
```

## 8. Logging

### 8.1 Log Levels

**Debug:**
- Token exchange requests/responses (sanitized)
- Role binding validation steps
- Credential refresh events

**Info:**
- Successful authentications
- Configuration changes
- Role CRUD operations

**Warn:**
- Failed authentication attempts
- Credential refresh failures
- Token validation warnings

**Error:**
- IAM API errors
- Metadata service errors
- Configuration errors

### 8.2 Log Format

```go
// Successful authentication
logger.Info("authentication successful",
    "role", roleName,
    "auth_type", authType,
    "account_id", accountID,
    "iam_id", iamID,
)

// Failed authentication
logger.Warn("authentication failed",
    "role", roleName,
    "auth_type", authType,
    "error", err.Error(),
)

// Token exchange
logger.Debug("exchanging credentials for IAM token",
    "auth_type", authType,
    "endpoint", iamEndpoint,
)
```

## 9. Performance Considerations

### 9.1 Caching

**Token Validation Cache:**
- Cache validated IAM tokens to avoid repeated validation
- Cache key: token hash
- Cache TTL: token expiration - 5 minutes
- Max cache size: 1000 entries

**Role Cache:**
- Cache role entries to avoid repeated storage reads
- Cache invalidation on role updates
- No expiration (invalidate on change)

### 9.2 Connection Pooling

- Reuse HTTP connections to IAM API
- Configure appropriate idle connection timeouts
- Set max idle connections per host

## 10. Security Best Practices

### 10.1 Credential Handling

```go
// Never log sensitive credentials
logger.Debug("authenticating with API key") // Good
logger.Debug("authenticating with API key", "apikey", apikey) // BAD!

// Sanitize error messages
if err != nil {
    return fmt.Errorf("authentication failed: %w", sanitizeError(err))
}

func sanitizeError(err error) error {
    // Remove any credential information from error messages
    msg := err.Error()
    msg = regexp.MustCompile(`apikey=[^&\s]+`).ReplaceAllString(msg, "apikey=***")
    msg = regexp.MustCompile(`cr_token=[^&\s]+`).ReplaceAllString(msg, "cr_token=***")
    return errors.New(msg)
}
```

### 10.2 Token Storage

- Never store API keys in Vault storage
- Never store CR tokens in Vault storage
- Only store role configuration and non-sensitive settings

### 10.3 TLS Verification

```go
// Always verify TLS certificates by default
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}

// Allow custom CA certificates if needed
if customCA != "" {
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM([]byte(customCA))
    transport.TLSClientConfig.RootCAs = caCertPool
}
```

## 11. Testing Mocks

### 11.1 Mock IAM API

```go
type MockIAMServer struct {
    server *httptest.Server
}

func NewMockIAMServer() *MockIAMServer {
    mux := http.NewServeMux()
    
    // Token exchange endpoint
    mux.HandleFunc("/identity/token", func(w http.ResponseWriter, r *http.Request) {
        // Parse request
        r.ParseForm()
        grantType := r.Form.Get("grant_type")
        
        if grantType == "urn:ibm:params:oauth:grant-type:apikey" {
            apiKey := r.Form.Get("apikey")
            // Validate and return token
            respondWithToken(w, apiKey)
        } else if grantType == "urn:ibm:params:oauth:grant-type:cr-token" {
            crToken := r.Form.Get("cr_token")
            profileID := r.Form.Get("profile_id")
            // Validate and return token
            respondWithTrustedProfileToken(w, crToken, profileID)
        }
    })
    
    return &MockIAMServer{
        server: httptest.NewServer(mux),
    }
}
```

### 11.2 Mock Metadata Service

```go
type MockMetadataServer struct {
    server *httptest.Server
}

func NewMockMetadataServer() *MockMetadataServer {
    mux := http.NewServeMux()
    
    // CR token endpoint
    mux.HandleFunc("/instance_identity/v1/token", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPut {
            w.WriteHeader(http.StatusMethodNotAllowed)
            return
        }
        
        // Return mock CR token
        json.NewEncoder(w).Encode(map[string]interface{}{
            "access_token": "mock-cr-token",
            "created_at":   time.Now().Format(time.RFC3339),
            "expires_at":   time.Now().Add(1 * time.Hour).Format(time.RFC3339),
            "expires_in":   3600,
        })
    })
    
    return &MockMetadataServer{
        server: httptest.NewServer(mux),
    }
}
```

## 12. Migration Path

For users migrating from other auth methods:

### 12.1 From AppRole

```bash
# Old AppRole configuration
vault write auth/approle/role/my-role \
    token_policies="my-policy" \
    token_ttl=1h

# New IBM Cloud configuration
vault write auth/ibmcloud/role/my-role \
    type=apikey \
    bound_account_id="abc123" \
    token_policies="my-policy" \
    token_ttl=1h
```

### 12.2 From Kubernetes

```bash
# Old Kubernetes configuration
vault write auth/kubernetes/role/my-role \
    bound_service_account_names=my-sa \
    bound_service_account_namespaces=default \
    token_policies="my-policy"

# New IBM Cloud Trusted Profile configuration
vault write auth/ibmcloud/role/my-role \
    type=trusted_profile \
    bound_trusted_profile_id="Profile-xxx" \
    bound_compute_resource_crn="crn:v1:bluemix:public:containers-kubernetes:*:a/abc123:*:*:*" \
    token_policies="my-policy"
```

## 13. Compliance and Audit

### 13.1 Audit Log Entries

All authentication attempts should be logged to Vault's audit log:

```json
{
  "type": "request",
  "auth": {
    "client_token": "hmac-sha256:...",
    "accessor": "hmac-sha256:...",
    "display_name": "ibmcloud-my-role",
    "policies": ["default", "my-policy"],
    "metadata": {
      "auth_type": "apikey",
      "account_id": "abc123",
      "iam_id": "IBMid-123456",
      "role": "my-role"
    }
  },
  "request": {
    "operation": "update",
    "path": "auth/ibmcloud/login",
    "data": {
      "role": "my-role",
      "type": "apikey"
    }
  }
}
```

### 13.2 Metrics

Emit metrics for monitoring:

```go
// Authentication attempts
metrics.IncrCounter([]string{"ibmcloud", "auth", "attempt"}, 1)

// Successful authentications
metrics.IncrCounter([]string{"ibmcloud", "auth", "success"}, 1)

// Failed authentications
metrics.IncrCounter([]string{"ibmcloud", "auth", "failure"}, 1)

// Authentication latency
metrics.MeasureSince([]string{"ibmcloud", "auth", "latency"}, start)

// Token exchange latency
metrics.MeasureSince([]string{"ibmcloud", "iam", "token_exchange"}, start)
```

## 14. Future Enhancements

### 14.1 Potential Features

1. **Service ID API Key Rotation**
   - Automatic rotation of service ID API keys
   - Integration with IBM Cloud IAM API key management

2. **Multi-Account Support**
   - Support for cross-account authentication
   - Assume role functionality similar to AWS STS

3. **Enhanced CRN Matching**
   - More sophisticated CRN pattern matching
   - Support for regular expressions

4. **Token Caching**
   - Cache IAM tokens to reduce API calls
   - Implement token refresh before expiration

5. **Custom Claims Validation**
   - Allow custom JWT claim validation
   - Support for additional identity attributes

### 14.2 Integration Opportunities

1. **IBM Cloud Secrets Manager**
   - Integration with IBM Cloud Secrets Manager for credential storage
   - Automatic secret rotation

2. **IBM Cloud Activity Tracker**
   - Send authentication events to Activity Tracker
   - Enhanced audit trail

3. **IBM Cloud IAM Access Groups**
   - Support for IAM access group membership validation
   - Dynamic policy assignment based on group membership
// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefixIBMCloud = "ibmcloud"

	// Default IAM endpoint
	defaultIAMEndpoint = "https://iam.cloud.ibm.com"
)

// Factory creates a new backend implementing the logical.Backend interface
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend

	// Lock for configuration changes
	configMutex sync.RWMutex

	// Lock for role changes
	roleMutex sync.RWMutex

	// IBM Cloud IAM client
	iamClient *IBMCloudIAMClient

	// Admin token management
	adminTokenMutex  sync.RWMutex
	adminToken       string
	adminTokenExpiry time.Time
}

// Backend creates a new backend with all paths configured
func Backend(conf *logical.BackendConfig) (*backend, error) {
	b := &backend{}

	b.Backend = &framework.Backend{
		AuthRenew: b.pathLoginRenew,
		Help:      backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: []*framework.Path{
			b.pathLogin(),
			b.pathListRole(),
			b.pathListRoles(),
			b.pathRole(),
			b.pathConfigIBMCloud(),
			b.pathConfigRotateRoot(),
		},
		Invalidate:  b.invalidate,
		BackendType: logical.TypeCredential,
		Clean:       b.cleanup,
	}

	return b, nil
}

// invalidate is called when a key is updated in storage
func (b *backend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.configMutex.Lock()
		b.iamClient = nil
		b.configMutex.Unlock()

		// Also invalidate admin token when config changes
		b.adminTokenMutex.Lock()
		b.adminToken = ""
		b.adminTokenExpiry = time.Time{}
		b.adminTokenMutex.Unlock()
	}
}

// cleanup is called when the backend is being shut down
func (b *backend) cleanup(ctx context.Context) {
	b.configMutex.Lock()
	b.iamClient = nil
	b.configMutex.Unlock()

	b.adminTokenMutex.Lock()
	b.adminToken = ""
	b.adminTokenExpiry = time.Time{}
	b.adminTokenMutex.Unlock()
}

// getAdminToken returns a valid admin token, refreshing if necessary
// The admin token is cached and automatically refreshed 5 minutes before expiration
func (b *backend) getAdminToken(ctx context.Context, s logical.Storage) (string, error) {
	b.adminTokenMutex.RLock()

	// Check if cached token is still valid (with 5 min buffer)
	if b.adminToken != "" && time.Until(b.adminTokenExpiry) > 5*time.Minute {
		token := b.adminToken
		b.adminTokenMutex.RUnlock()
		return token, nil
	}
	b.adminTokenMutex.RUnlock()

	// Need to refresh token
	b.adminTokenMutex.Lock()
	defer b.adminTokenMutex.Unlock()

	// Double-check after acquiring write lock
	if b.adminToken != "" && time.Until(b.adminTokenExpiry) > 5*time.Minute {
		return b.adminToken, nil
	}

	// Load config
	config, err := b.config(ctx, s)
	if err != nil {
		return "", err
	}
	if config == nil || config.APIKey == "" {
		return "", fmt.Errorf("no admin API key configured")
	}

	// Get IAM client
	client, err := b.getIAMClient(ctx, s)
	if err != nil {
		return "", err
	}

	// Exchange API key for token
	tokenResp, err := client.AuthenticateWithAPIKey(ctx, config.APIKey)
	if err != nil {
		return "", fmt.Errorf("failed to obtain admin token: %w", err)
	}

	// Cache token
	b.adminToken = tokenResp.AccessToken
	b.adminTokenExpiry = time.Unix(tokenResp.Expiration, 0)

	return b.adminToken, nil
}

// getIAMClient returns a configured IBM Cloud IAM client
func (b *backend) getIAMClient(ctx context.Context, s logical.Storage) (*IBMCloudIAMClient, error) {
	b.configMutex.RLock()
	if b.iamClient != nil {
		defer b.configMutex.RUnlock()
		return b.iamClient, nil
	}
	b.configMutex.RUnlock()

	b.configMutex.Lock()
	defer b.configMutex.Unlock()

	// Check again in case another goroutine created it
	if b.iamClient != nil {
		return b.iamClient, nil
	}

	// Load configuration
	config, err := b.config(ctx, s)
	if err != nil {
		return nil, err
	}

	// Use defaults if not configured
	iamEndpoint := defaultIAMEndpoint

	if config != nil && config.IAMEndpoint != "" {
		iamEndpoint = config.IAMEndpoint
	}

	// Create new client
	client, err := NewIBMCloudIAMClient(iamEndpoint, b.Logger())
	if err != nil {
		return nil, fmt.Errorf("failed to create IBM Cloud IAM client: %w", err)
	}

	b.iamClient = client
	return b.iamClient, nil
}

const backendHelp = `
The IBM Cloud auth method allows authentication using an IBM Cloud IAM access
token (JWT). Clients exchange their credential with IBM Cloud IAM themselves
and send only the resulting token to Vault. The token is verified offline
against the IAM JWKS and online via IAM introspect.

Roles have one of two types, which must match the identity kind in the token
(the sub_type claim):

1. apikey (User and ServiceId identities):
   - Validates against account ID, service ID, or user ID bindings

2. trusted_profile (Profile identities, e.g. VPC instances):
   - Validates against trusted profile ID and compute resource CRN patterns

Configuration:
  Configure the backend with IBM Cloud endpoints:
    $ vault write auth/ibmcloud/config \
        iam_endpoint="https://iam.cloud.ibm.com"

Roles:
  Create roles that define authentication requirements:
    $ vault write auth/ibmcloud/role/my-role \
        type=apikey \
        bound_account_id="abc123" \
        token_policies="default,my-policy"

Authentication:
  Authenticate using the login endpoint:
    $ vault write auth/ibmcloud/login \
        role=my-role \
        token="<iam-access-token>"
`

// Made with Bob

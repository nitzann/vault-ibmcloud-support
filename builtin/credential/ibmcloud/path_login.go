// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixIBMCloud,
			OperationVerb:   "login",
		},

		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role to authenticate against",
				Required:    true,
			},
			"type": {
				Type:        framework.TypeString,
				Description: "Type of authentication: 'apikey' or 'trusted_profile'",
				Required:    true,
			},
			"apikey": {
				Type:        framework.TypeString,
				Description: "(API Key type) IBM Cloud API key",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"cr_token": {
				Type:        framework.TypeString,
				Description: "(Trusted Profile type) Compute resource token (auto-fetched if not provided)",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"trusted_profile_id": {
				Type:        framework.TypeString,
				Description: "(Trusted Profile type) Override trusted profile ID",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginUpdate,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathLoginUpdate,
			},
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	authType := data.Get("type").(string)
	if authType == "" {
		return logical.ErrorResponse("missing type"), nil
	}

	// Validate auth type
	if authType != roleTypeAPIKey && authType != roleTypeTrustedProfile {
		return logical.ErrorResponse("type must be 'apikey' or 'trusted_profile'"), nil
	}

	// Load the role
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	// Verify role type matches request type
	if role.Type != authType {
		return logical.ErrorResponse("role type %q does not match request type %q", role.Type, authType), nil
	}

	// Get IAM client
	client, err := b.getIAMClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM client: %w", err)
	}

	// Authenticate based on type
	var identity *IdentityInfo
	switch authType {
	case roleTypeAPIKey:
		identity, err = b.authenticateAPIKey(ctx, client, data)
	case roleTypeTrustedProfile:
		identity, err = b.authenticateTrustedProfile(ctx, client, data, role)
	default:
		return logical.ErrorResponse("invalid authentication type"), nil
	}

	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Load config for account verification
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Perform dual-token verification for API key authentication
	if authType == roleTypeAPIKey && config != nil && config.AccountID != "" {
		// Get admin token for account verification
		adminToken, err := b.getAdminToken(ctx, req.Storage)
		if err != nil {
			return nil, fmt.Errorf("failed to get admin token: %w", err)
		}

		// Verify account membership using admin token
		if err := b.verifyAccountMembership(ctx, client, adminToken, identity, config.AccountID); err != nil {
			return logical.ErrorResponse("account verification failed: %s", err.Error()), nil
		}

		// Verify access group membership using user token if required
		if len(role.BoundAccessGroupIDs) > 0 {
			// Get user token from the authentication we just performed
			userAPIKey := data.Get("apikey").(string)
			userTokenResp, err := client.AuthenticateWithAPIKey(ctx, userAPIKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get user token for group verification: %w", err)
			}

			isMember, err := client.CheckAccessGroupMembership(ctx, userTokenResp.AccessToken, identity.IAMID, identity.AccountID, role.BoundAccessGroupIDs)
			if err != nil {
				return nil, fmt.Errorf("failed to check access group membership: %w", err)
			}
			if !isMember {
				return logical.ErrorResponse("user is not a member of required access groups"), nil
			}
		}
	}

	// Validate identity against role bindings (basic checks)
	if err := role.matchesIdentity(identity); err != nil {
		return logical.ErrorResponse("identity validation failed: %s", err.Error()), nil
	}

	// Check CIDR restrictions
	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return logical.ErrorResponse("failed to get connection information"), nil
		}

		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return logical.ErrorResponse("request originated from invalid CIDR"), nil
		}
	}

	// Generate auth response
	auth := &logical.Auth{
		Alias: &logical.Alias{
			Name: identity.IAMID,
		},
		InternalData: map[string]interface{}{
			"role": roleName,
		},
		Metadata: map[string]string{
			"account_id": identity.AccountID,
			"iam_id":     identity.IAMID,
			"subject":    identity.Subject,
			"auth_type":  authType,
		},
		DisplayName: identity.IAMID,
	}

	// Add type-specific metadata
	if authType == roleTypeAPIKey {
		auth.Metadata["subject_type"] = identity.SubjectType
	} else if authType == roleTypeTrustedProfile {
		auth.Metadata["trusted_profile_id"] = identity.TrustedProfileID
		if identity.ComputeResourceID != "" {
			auth.Metadata["compute_resource_id"] = identity.ComputeResourceID
		}
		if identity.CRN != "" {
			auth.Metadata["crn"] = identity.CRN
		}
	}

	role.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) authenticateAPIKey(ctx context.Context, client *IBMCloudIAMClient, data *framework.FieldData) (*IdentityInfo, error) {
	apiKey := data.Get("apikey").(string)
	if apiKey == "" {
		return nil, fmt.Errorf("missing apikey")
	}

	b.Logger().Debug("authenticating with API key", "apikey_prefix", apiKey[:min(10, len(apiKey))]+"...")

	// Exchange API key for IAM token
	tokenResp, err := client.AuthenticateWithAPIKey(ctx, apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with API key: %w", err)
	}

	b.Logger().Debug("successfully obtained IAM token", "token_type", tokenResp.TokenType, "expires_in", tokenResp.ExpiresIn)

	// Validate token and get identity information
	identity, err := client.ValidateToken(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	b.Logger().Debug("token validated successfully",
		"iam_id", identity.IAMID,
		"subject", identity.Subject,
		"subject_type", identity.SubjectType,
		"identifier", identity.Identifier,
		"account_id", identity.AccountID,
		"account_bss", identity.Account.BSS)

	return identity, nil
}

func (b *backend) authenticateTrustedProfile(ctx context.Context, client *IBMCloudIAMClient, data *framework.FieldData, role *ibmCloudRole) (*IdentityInfo, error) {
	crToken := data.Get("cr_token").(string)
	trustedProfileID := data.Get("trusted_profile_id").(string)

	// IAM requires a profile_id for the CR token exchange; default to the role's bound profile
	if trustedProfileID == "" {
		trustedProfileID = role.BoundTrustedProfileID
	}

	// If CR token not provided, fetch from metadata service
	if crToken == "" {
		var err error
		crToken, err = client.FetchCRToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch CR token from metadata service: %w", err)
		}
	}

	// Exchange CR token for IAM token
	tokenResp, err := client.AuthenticateWithCRToken(ctx, crToken, trustedProfileID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with CR token: %w", err)
	}

	// Validate token and get identity information
	identity, err := client.ValidateToken(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	return identity, nil
}

func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, fmt.Errorf("failed to fetch role name during renewal")
	}

	// Load the role
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, fmt.Errorf("role %q not found", roleName)
	}

	// Check CIDR restrictions
	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return nil, fmt.Errorf("failed to get connection information")
		}

		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, fmt.Errorf("request originated from invalid CIDR")
		}
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod

	return resp, nil
}

const pathLoginHelpSyn = `
Authenticate to Vault using IBM Cloud IAM credentials.
`

const pathLoginHelpDesc = `
This endpoint allows authentication using IBM Cloud IAM credentials.

Two authentication types are supported:

1. API Key Authentication:
   Authenticate using an IBM Cloud API key (user or service ID).

   Example:
     $ vault write auth/ibmcloud/login \
         role=my-role \
         type=apikey \
         apikey="your-api-key"

2. Trusted Profile Authentication:
   Authenticate using a compute resource token from a VPC instance.
   The CR token can be provided explicitly or auto-fetched from the
   metadata service.

   Example (auto-fetch):
     $ vault write auth/ibmcloud/login \
         role=my-role \
         type=trusted_profile

   Example (explicit token):
     $ vault write auth/ibmcloud/login \
         role=my-role \
         type=trusted_profile \
         cr_token="your-cr-token"

The authentication process:
1. Validates the provided credentials with IBM Cloud IAM
2. Extracts identity information from the IAM token
3. Validates the identity against the role's binding requirements
4. Issues a Vault token with the configured policies and properties
`

// verifyAccountMembership verifies that the identity belongs to the configured account
// Uses admin token to check service ID or user account membership
func (b *backend) verifyAccountMembership(ctx context.Context, client *IBMCloudIAMClient, adminToken string, identity *IdentityInfo, configAccountID string) error {
	b.Logger().Debug("verifying account membership",
		"identity_account", identity.AccountID,
		"configured_account", configAccountID,
		"subject_type", identity.SubjectType,
		"iam_id", identity.IAMID,
		"identifier", identity.Identifier)

	// Check if identity's account matches config account
	if identity.AccountID != configAccountID {
		return fmt.Errorf("identity account %s does not match configured account %s", identity.AccountID, configAccountID)
	}

	// For service IDs, verify they belong to the account using admin token
	if identity.SubjectType == "ServiceId" {
		b.Logger().Debug("verifying service ID", "iam_id", identity.IAMID, "identifier", identity.Identifier)
		serviceIDInfo, err := client.GetServiceID(ctx, adminToken, identity.IAMID)
		if err != nil {
			b.Logger().Error("failed to verify service ID", "error", err, "iam_id", identity.IAMID)
			return fmt.Errorf("failed to verify service ID: %w", err)
		}

		b.Logger().Debug("service ID verified", "service_id_account", serviceIDInfo.AccountID, "expected_account", configAccountID)

		if serviceIDInfo.AccountID != configAccountID {
			return fmt.Errorf("service ID belongs to account %s, expected %s", serviceIDInfo.AccountID, configAccountID)
		}
	} else {
		// For users, verify they have access to the account using admin token
		hasAccess, err := client.CheckUserAccount(ctx, adminToken, identity.IAMID, configAccountID)
		if err != nil {
			return fmt.Errorf("failed to verify user account access: %w", err)
		}

		if !hasAccess {
			return fmt.Errorf("user does not have access to account %s", configAccountID)
		}
	}

	return nil
}

// Made with Bob

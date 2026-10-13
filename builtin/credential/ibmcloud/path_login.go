// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"context"
	"errors"
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
			"token": {
				Type:        framework.TypeString,
				Description: "IBM Cloud IAM access token (JWT) obtained by the client",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
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

	token := data.Get("token").(string)
	if token == "" {
		return logical.ErrorResponse("missing token"), nil
	}

	// Load the role
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	// Get IAM client
	client, err := b.getIAMClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM client: %w", err)
	}

	// Verify the token offline (JWKS) and online (introspect)
	//
	// IBM IAM tokens carry no Vault-specific audience, so the account ID and
	// role binding checks below are the primary guard against token reuse.
	identity, err := client.VerifyToken(ctx, token)
	if err != nil {
		if errors.Is(err, errInvalidToken) {
			return logical.ErrorResponse("token verification failed: %s", err.Error()), nil
		}
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Derive the identity kind from the token and compare it to the role type
	authType, err := roleTypeForSubjectType(identity.SubjectType)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	if role.Type != authType {
		return logical.ErrorResponse("role type %q does not match token identity type %q", role.Type, authType), nil
	}

	// Load config for account verification
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// IAM tokens carry no Vault-specific audience, so when an account is
	// configured every identity type must belong to it. Trusted profile
	// identities are checked against the introspected account only; the
	// admin-token lookups below apply to user and service ID identities.
	if authType == roleTypeTrustedProfile && config != nil && config.AccountID != "" {
		if identity.AccountID != config.AccountID {
			return logical.ErrorResponse("account verification failed: identity account %s does not match configured account %s", identity.AccountID, config.AccountID), nil
		}
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
			isMember, err := client.CheckAccessGroupMembership(ctx, token, identity.IAMID, identity.AccountID, role.BoundAccessGroupIDs)
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

// roleTypeForSubjectType maps the IAM introspect sub_type claim to a role type.
func roleTypeForSubjectType(subType string) (string, error) {
	switch subType {
	case "User", "ServiceId":
		return roleTypeAPIKey, nil
	case "Profile":
		return roleTypeTrustedProfile, nil
	default:
		return "", fmt.Errorf("unsupported token subject type %q", subType)
	}
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
Authenticate to Vault using an IBM Cloud IAM access token.
`

const pathLoginHelpDesc = `
This endpoint authenticates using an IBM Cloud IAM access token (JWT) that the
client has already obtained from IBM Cloud IAM. Vault never receives API keys
or compute resource tokens. The vault CLI handler and the Vault Agent perform
the credential exchange locally.

Example:
  $ vault write auth/ibmcloud/login \
      role=my-role \
      token="<iam-access-token>"

The authentication process:
1. Verifies the token offline against the IAM JWKS (RS256 signature, issuer,
   exp and nbf). The key is selected by the token's kid header.
2. Confirms with IAM introspect that the token is active and reads the identity
   claims.
3. Derives the identity kind from the sub_type claim (User and ServiceId map to
   role type apikey, Profile maps to role type trusted_profile) and requires it
   to match the role's type.
4. Validates the identity against the role's binding requirements.
5. Issues a Vault token with the configured policies and properties.

The IAM access token is a bearer token valid for up to about 60 minutes. IBM
IAM tokens carry no Vault-specific audience, so the account ID and role binding
checks are the primary guard.
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

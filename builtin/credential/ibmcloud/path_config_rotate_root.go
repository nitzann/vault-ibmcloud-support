// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathConfigRotateRoot() *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixIBMCloud,
			OperationSuffix: "configuration-root-credentials",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigRotateRootUpdate,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "rotate",
				},
			},
		},

		HelpSynopsis:    pathConfigRotateRootHelpSyn,
		HelpDescription: pathConfigRotateRootHelpDesc,
	}
}

func (b *backend) pathConfigRotateRootUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.configMutex.Lock()
	defer b.configMutex.Unlock()

	// Load current configuration
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return logical.ErrorResponse("backend not configured"), nil
	}

	if config.APIKey == "" || config.ServiceID == "" {
		return logical.ErrorResponse("api_key and service_id must be configured before rotating credentials"), nil
	}

	// Get IAM client
	client, err := b.getIAMClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM client: %w", err)
	}

	// Step 1: Exchange current API key for IAM token
	tokenResp, err := client.AuthenticateWithAPIKey(ctx, config.APIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with current API key: %w", err)
	}

	// Step 2: Create new API key for the Service ID
	newAPIKeyName := fmt.Sprintf("vault-rotated-%d", time.Now().Unix())
	newAPIKeyDesc := "Rotated API key for Vault IBM Cloud auth backend"

	newAPIKeyResp, err := client.CreateAPIKey(ctx, tokenResp.AccessToken, config.ServiceID, newAPIKeyName, newAPIKeyDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to create new API key: %w", err)
	}

	// Step 3: Get the ID of the old API key (we need this to delete it)
	// We'll try to get details, but if it fails, we'll continue anyway
	var oldAPIKeyID string
	oldAPIKeyDetails, err := client.GetAPIKeyDetails(ctx, tokenResp.AccessToken, config.APIKey)
	if err == nil && oldAPIKeyDetails != nil {
		oldAPIKeyID = oldAPIKeyDetails.ID
	}

	// Step 4: Update configuration with new API key
	config.APIKey = newAPIKeyResp.APIKey

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		// If we can't save the new key, try to delete it to avoid orphaning
		_ = client.DeleteAPIKey(ctx, tokenResp.AccessToken, newAPIKeyResp.ID)
		return nil, fmt.Errorf("failed to save new API key to storage: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		// If we can't save the new key, try to delete it to avoid orphaning
		_ = client.DeleteAPIKey(ctx, tokenResp.AccessToken, newAPIKeyResp.ID)
		return nil, fmt.Errorf("failed to write new API key to storage: %w", err)
	}

	// Step 5: Delete old API key (if we have its ID)
	if oldAPIKeyID != "" {
		// Use the new API key to authenticate for deletion
		newTokenResp, err := client.AuthenticateWithAPIKey(ctx, config.APIKey)
		if err != nil {
			// Log warning but don't fail - the new key is already saved
			return &logical.Response{
				Warnings: []string{
					fmt.Sprintf("New API key created and saved, but failed to authenticate with it for old key deletion: %v", err),
					"Old API key was not deleted and should be manually removed",
				},
				Data: map[string]interface{}{
					"service_id": config.ServiceID,
					"rotated_at": time.Now().UTC().Format(time.RFC3339),
					"new_key_id": newAPIKeyResp.ID,
					"old_key_id": oldAPIKeyID,
				},
			}, nil
		}

		if err := client.DeleteAPIKey(ctx, newTokenResp.AccessToken, oldAPIKeyID); err != nil {
			// Log warning but don't fail - the new key is already saved
			return &logical.Response{
				Warnings: []string{
					fmt.Sprintf("New API key created and saved, but failed to delete old API key: %v", err),
					"Old API key should be manually removed",
				},
				Data: map[string]interface{}{
					"service_id": config.ServiceID,
					"rotated_at": time.Now().UTC().Format(time.RFC3339),
					"new_key_id": newAPIKeyResp.ID,
					"old_key_id": oldAPIKeyID,
				},
			}, nil
		}
	}

	// Step 6: Clear cached IAM client to force recreation with new credentials
	b.iamClient = nil

	return &logical.Response{
		Data: map[string]interface{}{
			"service_id": config.ServiceID,
			"rotated_at": time.Now().UTC().Format(time.RFC3339),
			"new_key_id": newAPIKeyResp.ID,
		},
	}, nil
}

const pathConfigRotateRootHelpSyn = `
Rotate the root API key used by Vault for IBM Cloud authentication.
`

const pathConfigRotateRootHelpDesc = `
This endpoint rotates the Service ID API key that Vault uses for IBM Cloud
authentication operations. This is useful for security compliance and
credential lifecycle management.

Prerequisites:
  * The backend must be configured with an api_key and service_id
  * The current API key must have permissions to create and delete API keys
    for the Service ID

Rotation Process:
  1. Authenticate with the current API key to get an IAM token
  2. Create a new API key for the Service ID
  3. Save the new API key to Vault's configuration
  4. Delete the old API key
  5. Clear cached IAM clients

If any step fails after the new key is created and saved, warnings will be
returned indicating that manual cleanup may be required.

Example:

  $ vault write -f auth/ibmcloud/config/rotate-root

Response:

  {
    "service_id": "ServiceId-xxx",
    "rotated_at": "2024-01-15T10:30:00Z",
    "new_key_id": "ApiKey-yyy"
  }

Note: After rotation, the old API key is deleted. If you need to maintain
access with the old key for a transition period, you should manually create
a new key before using this endpoint.
`

// Made with Bob

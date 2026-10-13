// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

// CLIHandler implements the Vault CLI auth handler interface
type CLIHandler struct{}

// Auth authenticates to Vault using IBM Cloud credentials
func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "ibmcloud"
	}

	role, ok := m["role"]
	if !ok {
		return nil, fmt.Errorf("'role' must be specified")
	}

	authType, ok := m["type"]
	if !ok {
		return nil, fmt.Errorf("'type' must be specified (apikey or trusted_profile)")
	}

	// Validate auth type
	if authType != "apikey" && authType != "trusted_profile" {
		return nil, fmt.Errorf("'type' must be 'apikey' or 'trusted_profile'")
	}

	// Build login data
	data := map[string]interface{}{
		"role": role,
		"type": authType,
	}

	// Handle API key authentication
	if authType == "apikey" {
		apiKey, ok := m["apikey"]
		if !ok {
			// Try to get from environment variable
			apiKey = os.Getenv("IBMCLOUD_API_KEY")
			if apiKey == "" {
				return nil, fmt.Errorf("'apikey' must be specified or set in IBMCLOUD_API_KEY environment variable")
			}
		}
		data["apikey"] = apiKey
	}

	// Handle trusted profile authentication
	if authType == "trusted_profile" {
		// CR token is optional - will be auto-fetched if not provided
		if crToken, ok := m["cr_token"]; ok {
			data["cr_token"] = crToken
		}

		// Trusted profile ID is optional
		if trustedProfileID, ok := m["trusted_profile_id"]; ok {
			data["trusted_profile_id"] = trustedProfileID
		}
	}

	path := fmt.Sprintf("auth/%s/login", mount)
	secret, err := c.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}

	return secret, nil
}

// Help returns the help text for the IBM Cloud auth method
func (h *CLIHandler) Help() string {
	help := `
Usage: vault login -method=ibmcloud [CONFIG K=V...]

  The IBM Cloud auth method allows users to authenticate with IBM Cloud
  IAM credentials. It supports two authentication types:

  1. API Key Authentication - Using IBM Cloud API keys
  2. Trusted Profile Authentication - Using compute resource tokens

  Authenticate using an API key:

      $ vault login -method=ibmcloud \
          role=my-role \
          type=apikey \
          apikey=your-api-key

  Authenticate using a trusted profile (auto-fetch CR token):

      $ vault login -method=ibmcloud \
          role=my-role \
          type=trusted_profile

  Authenticate using a trusted profile (explicit CR token):

      $ vault login -method=ibmcloud \
          role=my-role \
          type=trusted_profile \
          cr_token=your-cr-token

Configuration:

  mount=<string>
      Path where the IBM Cloud auth method is mounted. This is usually
      provided via the -path flag in the "vault login" command, but it can
      be specified here as well. If specified here, it takes precedence
      over the value for -path. The default value is "ibmcloud".

  role=<string>
      Name of the role to authenticate against. This is required.

  type=<string>
      Type of authentication: "apikey" or "trusted_profile". This is required.

  apikey=<string>
      (API Key type) IBM Cloud API key. Can also be specified via the
      IBMCLOUD_API_KEY environment variable.

  cr_token=<string>
      (Trusted Profile type) Compute resource token. If not provided, it will
      be automatically fetched from the VPC metadata service.

  trusted_profile_id=<string>
      (Trusted Profile type) Trusted profile ID to use. Optional.
`

	return strings.TrimSpace(help)
}

// Made with Bob

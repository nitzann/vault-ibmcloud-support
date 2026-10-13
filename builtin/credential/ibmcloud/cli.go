// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

// CLIHandler implements the Vault CLI auth handler interface
type CLIHandler struct{}

// Auth authenticates to Vault using IBM Cloud credentials. The credential is
// exchanged with IBM Cloud IAM locally; only the resulting IAM access token is
// sent to Vault.
func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "ibmcloud"
	}

	role, ok := m["role"]
	if !ok {
		return nil, fmt.Errorf("'role' must be specified")
	}

	token, err := resolveToken(m)
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"role":  role,
		"token": token,
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

// resolveToken returns the IAM access token to send to Vault, exchanging an
// API key or a compute resource token with IAM when no token is supplied.
func resolveToken(m map[string]string) (string, error) {
	if token := m["token"]; token != "" {
		return token, nil
	}

	iamEndpoint := m["iam_endpoint"]
	if iamEndpoint == "" {
		iamEndpoint = defaultIAMEndpoint
	}

	client, err := NewIBMCloudIAMClient(iamEndpoint, nil)
	if err != nil {
		return "", err
	}
	ctx := context.Background()

	if crToken := m["cr_token"]; crToken != "" {
		resp, err := client.AuthenticateWithCRToken(ctx, crToken, m["trusted_profile_id"])
		if err != nil {
			return "", fmt.Errorf("failed to exchange CR token: %w", err)
		}
		return resp.AccessToken, nil
	}

	apiKey := m["apikey"]
	if apiKey == "" {
		apiKey = os.Getenv("IBMCLOUD_API_KEY")
	}
	if apiKey == "" {
		return "", fmt.Errorf("one of 'token', 'apikey' (or IBMCLOUD_API_KEY) or 'cr_token' must be specified")
	}

	resp, err := client.AuthenticateWithAPIKey(ctx, apiKey)
	if err != nil {
		return "", fmt.Errorf("failed to exchange API key: %w", err)
	}
	return resp.AccessToken, nil
}

// Help returns the help text for the IBM Cloud auth method
func (h *CLIHandler) Help() string {
	help := `
Usage: vault login -method=ibmcloud [CONFIG K=V...]

  The IBM Cloud auth method authenticates with an IBM Cloud IAM access token.
  The CLI can obtain the token for you from an API key or a compute resource
  token. Only the resulting IAM access token is sent to Vault.

  Authenticate using an existing IAM access token:

      $ vault login -method=ibmcloud \
          role=my-role \
          token=your-iam-access-token

  Authenticate using an API key (user or service ID):

      $ vault login -method=ibmcloud \
          role=my-role \
          apikey=your-api-key

  Authenticate using a compute resource token and a trusted profile:

      $ vault login -method=ibmcloud \
          role=my-role \
          cr_token=your-cr-token \
          trusted_profile_id=Profile-xxxx

Configuration:

  mount=<string>
      Path where the IBM Cloud auth method is mounted. This is usually
      provided via the -path flag in the "vault login" command, but it can
      be specified here as well. If specified here, it takes precedence
      over the value for -path. The default value is "ibmcloud".

  role=<string>
      Name of the role to authenticate against. This is required.

  token=<string>
      IBM Cloud IAM access token, used as is.

  apikey=<string>
      IBM Cloud API key to exchange for an IAM access token. Can also be
      specified via the IBMCLOUD_API_KEY environment variable.

  cr_token=<string>
      Compute resource token to exchange for an IAM access token. Requires
      trusted_profile_id.

  trusted_profile_id=<string>
      Trusted profile ID used with cr_token.

  iam_endpoint=<string>
      IBM Cloud IAM endpoint used for the exchange. The default value is
      "https://iam.cloud.ibm.com".

  One of token, apikey (or IBMCLOUD_API_KEY) or cr_token is required.
`

	return strings.TrimSpace(help)
}

// Made with Bob

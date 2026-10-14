// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
)

// IBMCloudIAMClient wraps the IBM Cloud IAM API client
type IBMCloudIAMClient struct {
	iamEndpoint string
	httpClient  *http.Client
	logger      hclog.Logger
	jwks        *jwksVerifier
}

// NewIBMCloudIAMClient creates a new IBM Cloud IAM client
func NewIBMCloudIAMClient(iamEndpoint string, logger hclog.Logger) (*IBMCloudIAMClient, error) {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	return &IBMCloudIAMClient{
		iamEndpoint: iamEndpoint,
		httpClient:  httpClient,
		logger:      logger,
		jwks:        newJWKSVerifier(iamEndpoint, httpClient),
	}, nil
}

// IAMTokenResponse represents the response from IAM token API
type IAMTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Expiration   int64  `json:"expiration"`
	Scope        string `json:"scope"`
}

// IdentityInfo represents identity information extracted from IAM token
type IdentityInfo struct {
	Active            bool     `json:"active"`
	AccountID         string   `json:"account_id"`
	IAMID             string   `json:"iam_id"`
	Subject           string   `json:"sub"`
	SubjectType       string   `json:"sub_type"`
	Identifier        string   `json:"identifier"`
	TrustedProfileID  string   `json:"trusted_profile_id,omitempty"`
	ComputeResourceID string   `json:"compute_resource_id,omitempty"`
	CRN               string   `json:"crn,omitempty"`
	AccessGroupIDs    []string `json:"access_group_ids,omitempty"`
	Account           struct {
		BSS string `json:"bss"`
	} `json:"account"`
}

// APIKeyResponse represents the response from creating an API key
type APIKeyResponse struct {
	ID          string `json:"id"`
	APIKey      string `json:"apikey"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IAMID       string `json:"iam_id"`
	CreatedAt   string `json:"created_at"`
}

// AuthenticateWithAPIKey exchanges an API key for an IAM token
func (c *IBMCloudIAMClient) AuthenticateWithAPIKey(ctx context.Context, apiKey string) (*IAMTokenResponse, error) {
	apiURL := c.iamEndpoint + "/identity/token"
	c.logger.Debug("IBM Cloud IAM API call", "method", "POST", "url", apiURL, "endpoint", "token")

	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Set("apikey", apiKey)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	c.logger.Debug("request headers", "Content-Type", "application/x-www-form-urlencoded", "Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("IAM API call failed", "error", err)
		return nil, fmt.Errorf("failed to authenticate with API key: %w", err)
	}
	defer resp.Body.Close()

	c.logger.Debug("IAM API response", "status_code", resp.StatusCode, "status", resp.Status)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Error("IAM API error response", "status_code", resp.StatusCode, "body", string(body))
		return nil, fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp IAMTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	c.logger.Debug("token obtained successfully", "token_type", tokenResp.TokenType, "expires_in", tokenResp.ExpiresIn)

	return &tokenResp, nil
}

// AuthenticateWithCRToken exchanges a compute resource token for an IAM token.
// The server login path no longer calls it; it is kept for the client-side
// exchange in the CLI handler and Agent (plan sub-task 4).
func (c *IBMCloudIAMClient) AuthenticateWithCRToken(ctx context.Context, crToken, trustedProfileID string) (*IAMTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:cr-token")
	data.Set("cr_token", crToken)

	if trustedProfileID != "" {
		data.Set("profile_id", trustedProfileID)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.iamEndpoint+"/identity/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with CR token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp IAMTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// ExchangeVPCMetadata fetches an identity access token from the VPC metadata
// service (PUT /identity/v1/token) and exchanges it via the metadata service
// IAM token endpoint (POST /identity/v1/iam_tokens) for an IAM access token.
// If trustedProfileID is empty, the metadata service uses the default trusted
// profile linked to the compute instance.
func (c *IBMCloudIAMClient) ExchangeVPCMetadata(ctx context.Context, metadataEndpoint, trustedProfileID string) (*IAMTokenResponse, error) {
	if metadataEndpoint == "" {
		metadataEndpoint = defaultMetadataEndpoint
	}
	metadataEndpoint = strings.TrimRight(metadataEndpoint, "/")

	// Step 1: PUT /identity/v1/token
	tokenURL := fmt.Sprintf("%s/identity/v1/token?version=2022-03-01", metadataEndpoint)
	tokenReqBody := map[string]interface{}{
		"expires_in": 3600,
	}
	tokenReqJSON, err := json.Marshal(tokenReqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, tokenURL, bytes.NewReader(tokenReqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "ibm")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata identity token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("metadata identity token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var identityTokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&identityTokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode metadata identity token response: %w", err)
	}
	if identityTokenResp.AccessToken == "" {
		return nil, fmt.Errorf("empty access_token received from metadata identity token endpoint")
	}

	// Step 2: POST /identity/v1/iam_tokens
	iamTokensURL := fmt.Sprintf("%s/identity/v1/iam_tokens?version=2022-03-01", metadataEndpoint)
	var iamReqBody []byte
	if trustedProfileID != "" {
		bodyObj := map[string]interface{}{
			"trusted_profile": map[string]string{
				"id": trustedProfileID,
			},
		}
		iamReqBody, err = json.Marshal(bodyObj)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata iam_tokens request: %w", err)
		}
	}

	var iamReqReader io.Reader
	if len(iamReqBody) > 0 {
		iamReqReader = bytes.NewReader(iamReqBody)
	} else {
		iamReqReader = bytes.NewReader([]byte("{}"))
	}

	iamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, iamTokensURL, iamReqReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata iam_tokens request: %w", err)
	}
	iamReq.Header.Set("Metadata-Flavor", "ibm")
	iamReq.Header.Set("Authorization", "Bearer "+identityTokenResp.AccessToken)
	iamReq.Header.Set("Content-Type", "application/json")
	iamReq.Header.Set("Accept", "application/json")

	iamResp, err := c.httpClient.Do(iamReq)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange metadata token for IAM token: %w", err)
	}
	defer iamResp.Body.Close()

	if iamResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(iamResp.Body)
		if trustedProfileID == "" {
			return nil, fmt.Errorf("metadata IAM token exchange failed with status %d: %s (if the instance does not have a default trusted profile, specify trusted_profile_id)", iamResp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("metadata IAM token exchange failed with status %d: %s", iamResp.StatusCode, string(body))
	}

	var iamTokenResp IAMTokenResponse
	if err := json.NewDecoder(iamResp.Body).Decode(&iamTokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode metadata IAM token response: %w", err)
	}
	if iamTokenResp.AccessToken == "" {
		return nil, fmt.Errorf("empty access_token received from metadata IAM token endpoint")
	}

	return &iamTokenResp, nil
}

// VerifyToken verifies an IAM JWT offline against the IAM JWKS (signature,
// issuer, exp, nbf) and then online via IAM introspect (active flag and
// identity claims). Failures caused by the token itself wrap errInvalidToken.
func (c *IBMCloudIAMClient) VerifyToken(ctx context.Context, token string) (*IdentityInfo, error) {
	if err := c.jwks.verify(ctx, token); err != nil {
		return nil, err
	}
	return c.ValidateToken(ctx, token)
}

// ValidateToken introspects an IAM token and returns identity information.
// It returns an error wrapping errInvalidToken if IAM reports the token as inactive.
func (c *IBMCloudIAMClient) ValidateToken(ctx context.Context, token string) (*IdentityInfo, error) {
	apiURL := c.iamEndpoint + "/identity/introspect"
	c.logger.Debug("IBM Cloud IAM API call", "method", "POST", "url", apiURL, "endpoint", "introspect")

	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	c.logger.Debug("request headers", "Content-Type", "application/x-www-form-urlencoded", "Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("IAM API call failed", "error", err)
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	c.logger.Debug("IAM API response", "status_code", resp.StatusCode, "status", resp.Status)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Error("IAM API error response", "status_code", resp.StatusCode, "body", string(body))
		// IAM rejects tokens it considers invalid with 400/401; those are the
		// caller's problem, not an IAM outage.
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("%w: introspect rejected token with status %d", errInvalidToken, resp.StatusCode)
		}
		return nil, fmt.Errorf("token validation failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var info IdentityInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to decode identity info: %w", err)
	}

	if !info.Active {
		return nil, fmt.Errorf("%w: token is not active", errInvalidToken)
	}

	// IBM Cloud IAM returns account in nested structure: account.bss
	// Copy it to AccountID for easier access
	if info.AccountID == "" && info.Account.BSS != "" {
		info.AccountID = info.Account.BSS
		c.logger.Debug("extracted account from nested structure", "account_bss", info.Account.BSS)
	}

	c.logger.Debug("identity info extracted",
		"iam_id", info.IAMID,
		"subject", info.Subject,
		"subject_type", info.SubjectType,
		"identifier", info.Identifier,
		"account_id", info.AccountID)

	return &info, nil
}

// CreateAPIKey creates a new API key for a Service ID
func (c *IBMCloudIAMClient) CreateAPIKey(ctx context.Context, iamToken, serviceID, name, description string) (*APIKeyResponse, error) {
	payload := map[string]interface{}{
		"name":        name,
		"description": description,
		"iam_id":      serviceID,
		"account_id":  "", // Will be derived from the service ID
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.iamEndpoint+"/v1/apikeys", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+iamToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create API key with status %d: %s", resp.StatusCode, string(body))
	}

	var apiKeyResp APIKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiKeyResp); err != nil {
		return nil, fmt.Errorf("failed to decode API key response: %w", err)
	}

	return &apiKeyResp, nil
}

// DeleteAPIKey deletes an API key by ID
func (c *IBMCloudIAMClient) DeleteAPIKey(ctx context.Context, iamToken, apiKeyID string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.iamEndpoint+"/v1/apikeys/"+apiKeyID, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+iamToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete API key with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetAPIKeyDetails retrieves details about an API key
func (c *IBMCloudIAMClient) GetAPIKeyDetails(ctx context.Context, iamToken, apiKeyID string) (*APIKeyResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.iamEndpoint+"/v1/apikeys/"+apiKeyID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+iamToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key details: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get API key details with status %d: %s", resp.StatusCode, string(body))
	}

	var apiKeyResp APIKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiKeyResp); err != nil {
		return nil, fmt.Errorf("failed to decode API key response: %w", err)
	}

	return &apiKeyResp, nil
}

// ServiceIDInfo represents information about a service ID
type ServiceIDInfo struct {
	ID        string `json:"id"`
	IAMID     string `json:"iam_id"`
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
}

// GetServiceID retrieves service ID details using admin token
// This verifies that the service ID belongs to the configured account
func (c *IBMCloudIAMClient) GetServiceID(ctx context.Context, adminToken, serviceIDIAMID string) (*ServiceIDInfo, error) {
	// Extract service ID from IAM ID (format: iam-ServiceId-<uuid>)
	// IBM Cloud API expects the full ServiceId-<uuid> format, not just the UUID
	serviceID := strings.TrimPrefix(serviceIDIAMID, "iam-")

	apiURL := c.iamEndpoint + "/v1/serviceids/" + serviceID
	c.logger.Debug("IBM Cloud IAM API call", "method", "GET", "url", apiURL, "endpoint", "get_service_id")
	c.logger.Debug("service ID lookup", "iam_id", serviceIDIAMID, "extracted_id", serviceID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("IAM API call failed", "error", err)
		return nil, fmt.Errorf("failed to get service ID: %w", err)
	}
	defer resp.Body.Close()

	c.logger.Debug("IAM API response", "status_code", resp.StatusCode, "status", resp.Status)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Error("IAM API error response", "status_code", resp.StatusCode, "body", string(body))
		return nil, fmt.Errorf("failed to get service ID with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.logger.Debug("service ID response body", "body", string(body))

	var serviceIDInfo ServiceIDInfo
	if err := json.Unmarshal(body, &serviceIDInfo); err != nil {
		return nil, fmt.Errorf("failed to decode service ID response: %w", err)
	}

	c.logger.Debug("service ID info retrieved", "account_id", serviceIDInfo.AccountID, "name", serviceIDInfo.Name)

	return &serviceIDInfo, nil
}

// CheckUserAccount verifies that a user has access to the specified account
// Uses admin token to check user's account membership
func (c *IBMCloudIAMClient) CheckUserAccount(ctx context.Context, adminToken, userIAMID, accountID string) (bool, error) {
	// Use IAM Users API to verify user belongs to account
	// GET /v2/accounts/{account_id}/users/{user_id}
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/v2/accounts/%s/users/%s", c.iamEndpoint, accountID, userIAMID), nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to check user account: %w", err)
	}
	defer resp.Body.Close()

	// 200 = user has access, 404 = user not in account, other = error
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("failed to check user account with status %d: %s", resp.StatusCode, string(body))
	}
}

// AccessGroupMembership represents access group membership information
type AccessGroupMembership struct {
	Groups []AccessGroup `json:"groups"`
}

// AccessGroup represents an access group
type AccessGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CheckAccessGroupMembership verifies that a user/service ID is a member of specified access groups
// Uses user token to check their own group membership
func (c *IBMCloudIAMClient) CheckAccessGroupMembership(ctx context.Context, userToken, iamID, accountID string, requiredGroupIDs []string) (bool, error) {
	if len(requiredGroupIDs) == 0 {
		return true, nil // No groups required
	}

	// Get user's access group memberships
	// GET /v2/groups?account_id={account_id}&iam_id={iam_id}
	reqURL := fmt.Sprintf("%s/v2/groups?account_id=%s&iam_id=%s", c.iamEndpoint, url.QueryEscape(accountID), url.QueryEscape(iamID))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to check access group membership: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("failed to check access group membership with status %d: %s", resp.StatusCode, string(body))
	}

	var membership AccessGroupMembership
	if err := json.NewDecoder(resp.Body).Decode(&membership); err != nil {
		return false, fmt.Errorf("failed to decode access group membership: %w", err)
	}

	// Build set of user's group IDs
	userGroups := make(map[string]bool)
	for _, group := range membership.Groups {
		userGroups[group.ID] = true
	}

	// Check if user is in all required groups
	for _, requiredGroupID := range requiredGroupIDs {
		if !userGroups[requiredGroupID] {
			return false, nil
		}
	}

	return true, nil
}

// Made with Bob

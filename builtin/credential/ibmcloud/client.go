// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
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
	iamEndpoint      string
	metadataEndpoint string
	httpClient       *http.Client
	logger           hclog.Logger
}

// NewIBMCloudIAMClient creates a new IBM Cloud IAM client
func NewIBMCloudIAMClient(iamEndpoint, metadataEndpoint string, logger hclog.Logger) (*IBMCloudIAMClient, error) {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	return &IBMCloudIAMClient{
		iamEndpoint:      iamEndpoint,
		metadataEndpoint: metadataEndpoint,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
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

	c.logger.Debug("request payload", "grant_type", "urn:ibm:params:oauth:grant-type:apikey", "apikey", apiKey[:min(10, len(apiKey))]+"...")

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

// AuthenticateWithCRToken exchanges a compute resource token for an IAM token
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

// FetchCRToken retrieves a compute resource token from the VPC metadata service
func (c *IBMCloudIAMClient) FetchCRToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "PUT", c.metadataEndpoint+"/identity/v1/token?version=2025-08-26", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Metadata-Flavor", "ibm")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch CR token: %w", err)
	}
	defer resp.Body.Close()

	// The VPC metadata service returns 201 Created for PUT /identity/v1/token.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to fetch CR token with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode CR token response: %w", err)
	}

	return result.AccessToken, nil
}

// ValidateToken validates an IAM token and returns identity information
func (c *IBMCloudIAMClient) ValidateToken(ctx context.Context, token string) (*IdentityInfo, error) {
	apiURL := c.iamEndpoint + "/identity/introspect"
	c.logger.Debug("IBM Cloud IAM API call", "method", "POST", "url", apiURL, "endpoint", "introspect")

	data := url.Values{}
	data.Set("token", token)

	c.logger.Debug("request payload", "token", token[:min(20, len(token))]+"...")

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
		return nil, fmt.Errorf("token validation failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.logger.Debug("introspect response body", "body", string(body))

	var info IdentityInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to decode identity info: %w", err)
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

	c.logger.Debug("request headers", "Authorization", "Bearer "+adminToken[:min(20, len(adminToken))]+"...", "Accept", "application/json")

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

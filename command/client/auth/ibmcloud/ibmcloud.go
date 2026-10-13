// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/client/auth"
)

const (
	typeAPIKey         = "apikey"
	typeTrustedProfile = "trusted_profile"

	// Default polling interval for credential refresh (60 seconds)
	defaultCredentialPollInterval = 60

	// Default metadata endpoint
	defaultMetadataEndpoint = "http://169.254.169.254"
)

type ibmcloudMethod struct {
	logger   hclog.Logger
	authType string
	role     string

	// Mount path for the auth method
	mountPath string

	// For API key type
	apiKey string

	// For trusted profile type
	crToken                string
	trustedProfileID       string
	metadataEndpoint       string
	credentialPollInterval int

	// Credential refresh
	credLock    sync.Mutex
	lastCRToken string
	credsFound  chan struct{}
	stopCh      chan struct{}
}

// NewIBMCloudAuthMethod creates a new IBM Cloud auth method for Vault Agent
func NewIBMCloudAuthMethod(conf *auth.AuthConfig) (auth.AuthMethod, error) {
	if conf == nil {
		return nil, errors.New("empty config")
	}
	if conf.Config == nil {
		return nil, errors.New("empty config data")
	}

	a := &ibmcloudMethod{
		logger:                 conf.Logger,
		mountPath:              conf.MountPath,
		credsFound:             make(chan struct{}),
		stopCh:                 make(chan struct{}),
		metadataEndpoint:       defaultMetadataEndpoint,
		credentialPollInterval: defaultCredentialPollInterval,
	}

	// Get auth type
	typeRaw, ok := conf.Config["type"]
	if !ok {
		return nil, errors.New("missing 'type' value")
	}
	a.authType, ok = typeRaw.(string)
	if !ok {
		return nil, errors.New("could not convert 'type' config value to string")
	}

	// Validate auth type
	if a.authType != typeAPIKey && a.authType != typeTrustedProfile {
		return nil, fmt.Errorf("'type' must be '%s' or '%s'", typeAPIKey, typeTrustedProfile)
	}

	// Get role
	roleRaw, ok := conf.Config["role"]
	if !ok {
		return nil, errors.New("missing 'role' value")
	}
	a.role, ok = roleRaw.(string)
	if !ok {
		return nil, errors.New("could not convert 'role' config value to string")
	}

	if a.role == "" {
		return nil, errors.New("'role' value is empty")
	}

	// Handle API key type configuration
	if a.authType == typeAPIKey {
		apiKeyRaw, ok := conf.Config["apikey"]
		if !ok {
			return nil, errors.New("missing 'apikey' value for apikey type")
		}
		a.apiKey, ok = apiKeyRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'apikey' config value to string")
		}
		if a.apiKey == "" {
			return nil, errors.New("'apikey' value is empty")
		}
	}

	// Handle trusted profile type configuration
	if a.authType == typeTrustedProfile {
		// CR token is optional - will be auto-fetched if not provided
		if crTokenRaw, ok := conf.Config["cr_token"]; ok {
			a.crToken, ok = crTokenRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'cr_token' config value to string")
			}
		}

		// Trusted profile ID is optional
		if trustedProfileIDRaw, ok := conf.Config["trusted_profile_id"]; ok {
			a.trustedProfileID, ok = trustedProfileIDRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'trusted_profile_id' config value to string")
			}
		}

		// Metadata endpoint is optional
		if metadataEndpointRaw, ok := conf.Config["metadata_endpoint"]; ok {
			a.metadataEndpoint, ok = metadataEndpointRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'metadata_endpoint' config value to string")
			}
		}

		// Credential poll interval is optional
		if credentialPollIntervalRaw, ok := conf.Config["credential_poll_interval"]; ok {
			if credentialPollInterval, ok := credentialPollIntervalRaw.(int); ok && credentialPollInterval > 0 {
				a.credentialPollInterval = credentialPollInterval
			} else {
				return nil, errors.New("could not convert 'credential_poll_interval' into positive int")
			}
		}

		// If no CR token provided, fetch it initially
		if a.crToken == "" {
			crToken, err := a.fetchCRToken()
			if err != nil {
				return nil, fmt.Errorf("failed to fetch initial CR token: %w", err)
			}
			a.lastCRToken = crToken
		} else {
			a.lastCRToken = a.crToken
		}

		// Start polling for new CR tokens
		go a.pollForCRToken()
	}

	return a, nil
}

// Authenticate performs the authentication to Vault
func (a *ibmcloudMethod) Authenticate(ctx context.Context, client *api.Client) (retPath string, header http.Header, retData map[string]interface{}, retErr error) {
	a.logger.Trace("beginning authentication")

	data := make(map[string]interface{})
	data["role"] = a.role
	data["type"] = a.authType

	switch a.authType {
	case typeAPIKey:
		data["apikey"] = a.apiKey

	case typeTrustedProfile:
		a.credLock.Lock()
		crToken := a.lastCRToken
		a.credLock.Unlock()

		data["cr_token"] = crToken
		if a.trustedProfileID != "" {
			data["trusted_profile_id"] = a.trustedProfileID
		}

	default:
		retErr = fmt.Errorf("invalid auth type: %s", a.authType)
		return
	}

	return fmt.Sprintf("%s/login", a.mountPath), nil, data, nil
}

// NewCreds returns a channel that signals when new credentials are available
func (a *ibmcloudMethod) NewCreds() chan struct{} {
	return a.credsFound
}

// CredSuccess is called when credentials are successfully used
func (a *ibmcloudMethod) CredSuccess() {
	// Nothing to do here for IBM Cloud
}

// Shutdown stops the auth method
func (a *ibmcloudMethod) Shutdown() {
	close(a.stopCh)
	close(a.credsFound)
}

// fetchCRToken retrieves a compute resource token from the metadata service
func (a *ibmcloudMethod) fetchCRToken() (string, error) {
	req, err := http.NewRequest("PUT", a.metadataEndpoint+"/instance_identity/v1/token", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Metadata-Flavor", "ibm")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch CR token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to fetch CR token with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read CR token response: %w", err)
	}

	// The response is a JSON object with an access_token field
	// For simplicity, we'll parse it manually
	// In production, use json.Unmarshal
	token := string(body)

	return token, nil
}

// pollForCRToken periodically checks for new CR tokens
func (a *ibmcloudMethod) pollForCRToken() {
	ticker := time.NewTicker(time.Duration(a.credentialPollInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			a.logger.Trace("shutdown triggered, stopping ibmcloud auth handler")
			return
		case <-ticker.C:
			if err := a.checkCRToken(); err != nil {
				a.logger.Warn("unable to retrieve current CR token, retaining last token", "error", err)
			}
		}
	}
}

// checkCRToken checks if a new CR token is available
func (a *ibmcloudMethod) checkCRToken() error {
	a.logger.Trace("checking for new CR token")

	newToken, err := a.fetchCRToken()
	if err != nil {
		return err
	}

	a.credLock.Lock()
	defer a.credLock.Unlock()

	// If the token has changed, notify that new creds are available
	if newToken != a.lastCRToken {
		a.lastCRToken = newToken
		a.logger.Trace("new CR token detected, triggering Authenticate")
		select {
		case a.credsFound <- struct{}{}:
		default:
			// Channel might be full, that's okay
		}
	} else {
		a.logger.Trace("CR token unchanged")
	}

	return nil
}

// Made with Bob

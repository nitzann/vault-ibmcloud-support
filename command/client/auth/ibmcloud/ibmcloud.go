// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/ibmcloud"
	"github.com/hashicorp/vault/command/client/auth"
)

const (
	typeAPIKey         = "apikey"
	typeTrustedProfile = "trusted_profile"

	// Default polling interval for credential refresh (60 seconds)
	defaultCredentialPollInterval = 60

	// Default metadata endpoint
	defaultMetadataEndpoint = "http://169.254.169.254"

	// Default IAM endpoint
	defaultIAMEndpoint = "https://iam.cloud.ibm.com"
)

type ibmcloudMethod struct {
	logger   hclog.Logger
	authType string
	role     string

	// Mount path for the auth method
	mountPath string

	// Endpoints
	iamEndpoint      string
	metadataEndpoint string

	// For API key type
	apiKey string

	// For trusted profile type
	crToken                string
	trustedProfileID       string
	credentialPollInterval int

	// Credential refresh
	credLock     sync.Mutex
	lastIAMToken string
	// credsFound is non-nil only when the metadata polling goroutine is
	// running (i.e. typeTrustedProfile without a static cr_token).
	// NewCreds() returns nil for all other cases so the auth handler
	// framework substitutes an inert channel and never blocks.
	credsFound chan struct{}
	stopCh     chan struct{}
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
		stopCh:                 make(chan struct{}),
		iamEndpoint:            defaultIAMEndpoint,
		metadataEndpoint:       defaultMetadataEndpoint,
		credentialPollInterval: defaultCredentialPollInterval,
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

	// Endpoints overrides (optional)
	if iamEndpointRaw, ok := conf.Config["iam_endpoint"]; ok {
		if iamEndpoint, ok := iamEndpointRaw.(string); ok && iamEndpoint != "" {
			a.iamEndpoint = iamEndpoint
		} else {
			return nil, errors.New("could not convert 'iam_endpoint' config value to string")
		}
	}

	if metadataEndpointRaw, ok := conf.Config["metadata_endpoint"]; ok {
		if metadataEndpoint, ok := metadataEndpointRaw.(string); ok && metadataEndpoint != "" {
			a.metadataEndpoint = metadataEndpoint
		} else {
			return nil, errors.New("could not convert 'metadata_endpoint' config value to string")
		}
	}

	// Get auth type
	if typeRaw, ok := conf.Config["type"]; ok {
		a.authType, ok = typeRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'type' config value to string")
		}
	} else {
		// Infer type if omitted
		if _, ok := conf.Config["apikey"]; ok {
			a.authType = typeAPIKey
		} else if _, ok := conf.Config["cr_token"]; ok || conf.Config["trusted_profile_id"] != nil {
			a.authType = typeTrustedProfile
		} else if os.Getenv("IBMCLOUD_API_KEY") != "" {
			a.authType = typeAPIKey
		} else {
			return nil, errors.New("missing 'type' value")
		}
	}

	// Validate auth type
	if a.authType != typeAPIKey && a.authType != typeTrustedProfile {
		return nil, fmt.Errorf("'type' must be '%s' or '%s'", typeAPIKey, typeTrustedProfile)
	}

	// Handle API key type configuration
	if a.authType == typeAPIKey {
		if apiKeyRaw, ok := conf.Config["apikey"]; ok {
			a.apiKey, ok = apiKeyRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'apikey' config value to string")
			}
		}
		if a.apiKey == "" {
			a.apiKey = os.Getenv("IBMCLOUD_API_KEY")
		}
		if a.apiKey == "" {
			return nil, errors.New("missing 'apikey' value for apikey type (or set IBMCLOUD_API_KEY)")
		}
	}

	// Handle trusted profile type configuration
	if a.authType == typeTrustedProfile {
		if crTokenRaw, ok := conf.Config["cr_token"]; ok {
			a.crToken, ok = crTokenRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'cr_token' config value to string")
			}
		}

		if trustedProfileIDRaw, ok := conf.Config["trusted_profile_id"]; ok {
			a.trustedProfileID, ok = trustedProfileIDRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'trusted_profile_id' config value to string")
			}
		}

		if credentialPollIntervalRaw, ok := conf.Config["credential_poll_interval"]; ok {
			if credentialPollInterval, ok := credentialPollIntervalRaw.(int); ok && credentialPollInterval > 0 {
				a.credentialPollInterval = credentialPollInterval
			} else {
				return nil, errors.New("could not convert 'credential_poll_interval' into positive int")
			}
		}

		// When using metadata service (no static cr_token), poll periodically
		// to detect refreshed credentials. A non-nil credsFound tells the auth
		// handler framework to re-authenticate when a new token arrives.
		if a.crToken == "" {
			a.credsFound = make(chan struct{})
			go a.pollForCredentials()
		}
	}

	return a, nil
}

// Authenticate performs the authentication to Vault
func (a *ibmcloudMethod) Authenticate(ctx context.Context, client *api.Client) (retPath string, header http.Header, retData map[string]interface{}, retErr error) {
	a.logger.Trace("beginning authentication")

	iamClient, err := ibmcloud.NewIBMCloudIAMClient(a.iamEndpoint, a.logger)
	if err != nil {
		retErr = fmt.Errorf("failed to create IAM client: %w", err)
		return
	}

	var iamToken string
	switch a.authType {
	case typeAPIKey:
		resp, err := iamClient.AuthenticateWithAPIKey(ctx, a.apiKey)
		if err != nil {
			retErr = fmt.Errorf("failed to exchange API key: %w", err)
			return
		}
		iamToken = resp.AccessToken

	case typeTrustedProfile:
		if a.crToken != "" {
			resp, err := iamClient.AuthenticateWithCRToken(ctx, a.crToken, a.trustedProfileID)
			if err != nil {
				retErr = fmt.Errorf("failed to exchange CR token: %w", err)
				return
			}
			iamToken = resp.AccessToken
		} else {
			resp, err := iamClient.ExchangeVPCMetadata(ctx, a.metadataEndpoint, a.trustedProfileID)
			if err != nil {
				retErr = fmt.Errorf("failed to exchange VPC metadata token: %w", err)
				return
			}
			iamToken = resp.AccessToken
		}

	default:
		retErr = fmt.Errorf("invalid auth type: %s", a.authType)
		return
	}

	a.credLock.Lock()
	a.lastIAMToken = iamToken
	a.credLock.Unlock()

	data := map[string]interface{}{
		"role":  a.role,
		"token": iamToken,
	}

	return fmt.Sprintf("%s/login", a.mountPath), nil, data, nil
}

// NewCreds returns a channel that signals when new credentials are available.
// Returns nil when no polling goroutine is running (static cr_token or apikey),
// which causes the auth handler framework to substitute an inert channel.
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
}

// pollForCredentials periodically checks for new credentials from the metadata service
func (a *ibmcloudMethod) pollForCredentials() {
	ticker := time.NewTicker(time.Duration(a.credentialPollInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			a.logger.Trace("shutdown triggered, stopping ibmcloud auth handler")
			return
		case <-ticker.C:
			if err := a.checkCredentials(); err != nil {
				a.logger.Warn("unable to retrieve current credentials from metadata service", "error", err)
			}
		}
	}
}

// checkCredentials checks if new credentials are available
func (a *ibmcloudMethod) checkCredentials() error {
	a.logger.Trace("checking for new credentials from metadata service")

	iamClient, err := ibmcloud.NewIBMCloudIAMClient(a.iamEndpoint, a.logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := iamClient.ExchangeVPCMetadata(ctx, a.metadataEndpoint, a.trustedProfileID)
	if err != nil {
		return err
	}

	a.credLock.Lock()
	defer a.credLock.Unlock()

	if resp.AccessToken != a.lastIAMToken {
		a.logger.Trace("new IAM token detected from metadata service, triggering Authenticate")
		select {
		case a.credsFound <- struct{}{}:
		case <-a.stopCh:
		default:
		}
	}

	return nil
}

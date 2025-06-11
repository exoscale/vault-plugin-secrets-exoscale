package exoscale

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"

	egoscale "github.com/exoscale/egoscale/v2"
	exoapi "github.com/exoscale/egoscale/v2/api"
	"github.com/exoscale/egoscale/v2/oapi"
	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
)

var ErrorBackendNotConfigured = errors.New(`Exoscale secret engine not configured
hint: vault path-help exoscale/config/root # (replace "exoscale" by your mount point)`)

// egoscaleClient is implemented by egoscale and by a mock for testing
//
//go:generate mockery --name egoscaleClient
type egoscaleClient interface {
	CreateIAMAccessKey(context.Context, string, string, ...egoscale.CreateIAMAccessKeyOpt) (*egoscale.IAMAccessKey, error)
	RevokeIAMAccessKey(context.Context, string, *egoscale.IAMAccessKey) error

	CreateApiKeyWithResponse(ctx context.Context, body oapi.CreateApiKeyJSONRequestBody, reqEditors ...oapi.RequestEditorFn) (*oapi.CreateApiKeyResponse, error)
	DeleteApiKeyWithResponse(ctx context.Context, id string, reqEditors ...oapi.RequestEditorFn) (*oapi.DeleteApiKeyResponse, error)
	GetIamRoleWithResponse(ctx context.Context, id string, reqEditors ...oapi.RequestEditorFn) (*oapi.GetIamRoleResponse, error)
	ListIamRolesWithResponse(ctx context.Context, reqEditors ...oapi.RequestEditorFn) (*oapi.ListIamRolesResponse, error)
}

// Exoscale is an abstraction over the Exoscale API
type Exoscale struct {
	sync.RWMutex
	egoscaleClient
	reqEndpoint exoapi.ReqEndpoint

	apiKey    string
	apiSecret string

	configured       bool
	apiKeyNamePrefix string
}

func (e *Exoscale) LoadConfigFromStorage(ctx context.Context, storage logical.Storage) error {
	var config ExoscaleConfig

	entry, err := storage.Get(ctx, configRootStoragePath)
	if err != nil {
		return fmt.Errorf("unable to retrieve backend config from storage: %w", err)

	}

	if entry == nil {
		return nil
	}

	if err := entry.DecodeJSON(&config); err != nil {
		return fmt.Errorf("failed to decode backend config %w", err)
	}

	if err := e.LoadConfig(config); err != nil {
		return err
	}

	return nil
}

func (e *Exoscale) LoadConfig(cfg ExoscaleConfig) error {
	exo, err := egoscale.NewClient(cfg.RootAPIKey, cfg.RootAPISecret)
	if err != nil {
		return fmt.Errorf("unable to initialize Exoscale client: %w", err)
	}

	reqEndpoint := exoapi.NewReqEndpoint(cfg.APIEnvironment, cfg.Zone)

	e.Lock()
	egoscale.UserAgent = fmt.Sprintf("Exoscale-Vault-Plugin-Secrets/%s (%s) %s",
		version.Version, version.Commit, egoscale.UserAgent)
	e.egoscaleClient = exo
	e.reqEndpoint = reqEndpoint
	e.configured = true
	e.apiKey = cfg.RootAPIKey
	e.apiSecret = cfg.RootAPISecret
	e.apiKeyNamePrefix = cfg.APIKeyNamePrefix
	e.Unlock()

	return nil
}

// v2ParseIAMResource parses a string-encoded IAM access key resource formatted such as
// DOMAIN/TYPE:NAME and deserializes it into an egoscale.IAMAccessKeyResource struct.
func V2ParseIAMResource(v string) (*egoscale.IAMAccessKeyResource, error) {
	var iamAccessKeyResource egoscale.IAMAccessKeyResource

	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid resource format %q", v)
	}
	iamAccessKeyResource.ResourceName = parts[1]

	parts = strings.SplitN(parts[0], "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid resource format %q", v)
	}
	iamAccessKeyResource.Domain = parts[0]
	iamAccessKeyResource.ResourceType = parts[1]

	if iamAccessKeyResource.Domain == "" ||
		iamAccessKeyResource.ResourceType == "" ||
		iamAccessKeyResource.ResourceName == "" {
		return nil, fmt.Errorf("invalid resource format %q", v)
	}

	return &iamAccessKeyResource, nil
}

// V2CreateAccessKey creates a IAMv2 Access Key
func (e *Exoscale) V2CreateAccessKey(ctx context.Context, roleName string, reqDisplayName string, role Role) (*egoscale.IAMAccessKey, error) {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return nil, ErrorBackendNotConfigured
	}

	opts := make([]egoscale.CreateIAMAccessKeyOpt, 0)
	if len(role.Operations) > 0 {
		opts = append(opts, egoscale.CreateIAMAccessKeyWithOperations(role.Operations))
	}

	if len(role.Resources) > 0 {
		resources := make([]egoscale.IAMAccessKeyResource, len(role.Resources))
		for i, rs := range role.Resources {
			r, err := V2ParseIAMResource(rs)
			if err != nil {
				return nil, fmt.Errorf("invalid API resource %q", rs)
			}
			resources[i] = *r
		}
		opts = append(opts, egoscale.CreateIAMAccessKeyWithResources(resources))
	}

	if len(role.Tags) > 0 {
		opts = append(opts, egoscale.CreateIAMAccessKeyWithTags(role.Tags))
	}

	var prefix string
	if e.apiKeyNamePrefix != "" {
		prefix = e.apiKeyNamePrefix + "-"
	}

	iamAPIKey, err := e.CreateIAMAccessKey(
		exoapi.WithEndpoint(ctx, e.reqEndpoint),
		e.reqEndpoint.Zone(),
		fmt.Sprintf("vault-%s%s-%s-%d-deprecated", prefix, roleName, reqDisplayName, time.Now().UnixNano()),
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create a new API key: %w", err)
	}

	return iamAPIKey, nil
}

// V2RevokeAccessKey revokes a IAMv2 Access Key
func (e *Exoscale) V2RevokeAccessKey(ctx context.Context, key string) error {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return ErrorBackendNotConfigured
	}

	return e.RevokeIAMAccessKey(exoapi.WithEndpoint(ctx, e.reqEndpoint), e.reqEndpoint.Zone(), &egoscale.IAMAccessKey{Key: &key})
}

// V3CreateAPIKey creates a IAMv3 API Key
func (e *Exoscale) V3CreateAPIKey(ctx context.Context, roleName string, reqDisplayName string, role Role) (*oapi.IamApiKeyCreated, error) {
	e.RLock()
	defer e.RUnlock()

	var prefix string
	if e.apiKeyNamePrefix != "" {
		prefix = e.apiKeyNamePrefix + "-"
	}

	if !e.configured {
		return nil, ErrorBackendNotConfigured
	}

	resp, err := e.CreateApiKeyWithResponse(exoapi.WithEndpoint(ctx, e.reqEndpoint), oapi.CreateApiKeyJSONRequestBody{
		Name:   fmt.Sprintf("vault-%s%s-%s-%d", prefix, roleName, reqDisplayName, time.Now().UnixNano()),
		RoleId: role.IAMRoleID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create api key: %w", err)
	}

	return resp.JSON200, nil
}

// V3DeleteAPIKey deletes a IAMv3 API Key
func (e *Exoscale) V3DeleteAPIKey(ctx context.Context, key string) error {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return ErrorBackendNotConfigured
	}

	resp, err := e.DeleteApiKeyWithResponse(exoapi.WithEndpoint(ctx, e.reqEndpoint), key)
	if err != nil {
		return err
	}
	if *resp.JSON200.State != oapi.OperationStateSuccess { // TODO(antoine): check if the state is "pending" and poll
		return errors.New(*resp.JSON200.Message)
	}

	fmt.Println(*resp.JSON200.State)

	return nil
}

// V3GetRole takes a role ID or name and returns a role ID if that role exists
func (e *Exoscale) V3GetRole(ctx context.Context, role string) (*oapi.IamRole, error) {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return nil, ErrorBackendNotConfigured
	}

	_, err := uuid.ParseUUID(role)
	if err == nil {
		rolebyid, err := e.GetIamRoleWithResponse(exoapi.WithEndpoint(ctx, e.reqEndpoint), role)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch role %q by ID: %w", role, err)
		}
		return rolebyid.JSON200, nil
	}

	allroles, err := e.ListIamRolesWithResponse(exoapi.WithEndpoint(ctx, e.reqEndpoint))
	if err != nil {
		return nil, err
	}

	if allroles.JSON200 != nil && allroles.JSON200.IamRoles != nil {
		for _, r := range *allroles.JSON200.IamRoles {
			if *r.Name == role {
				return &r, nil
			}
		}
	}

	return nil, fmt.Errorf("role %q not found", role)
}

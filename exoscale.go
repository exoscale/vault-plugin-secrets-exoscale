package exoscale

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	egoscale "github.com/exoscale/egoscale/v2"
	exoapi "github.com/exoscale/egoscale/v2/api"
	"github.com/exoscale/egoscale/v2/oapi"
	"github.com/hashicorp/vault/sdk/logical"
)

// egoscaleClient is implemented by egoscale and by a mock for testing
type egoscaleClient interface {
	CreateIAMAccessKey(context.Context, string, string, ...egoscale.CreateIAMAccessKeyOpt) (*egoscale.IAMAccessKey, error)
	RevokeIAMAccessKey(context.Context, string, *egoscale.IAMAccessKey) error

	CreateApiKeyWithResponse(ctx context.Context, body oapi.CreateApiKeyJSONRequestBody, reqEditors ...oapi.RequestEditorFn) (*oapi.CreateApiKeyResponse, error)
	DeleteApiKeyWithResponse(ctx context.Context, id string, reqEditors ...oapi.RequestEditorFn) (*oapi.DeleteApiKeyResponse, error)
	GetIamRoleWithResponse(ctx context.Context, id string, reqEditors ...oapi.RequestEditorFn) (*oapi.GetIamRoleResponse, error)
	ListIamRolesWithResponse(ctx context.Context, reqEditors ...oapi.RequestEditorFn) (*oapi.ListIamRolesResponse, error)
}

// exoscale is an abstraction over the Exoscale API
type exoscale struct {
	sync.RWMutex
	egoscaleClient
	apiKey      string
	reqEndpoint exoapi.ReqEndpoint
	configured  bool
}

func (e *exoscale) LoadConfigFromStorage(ctx context.Context, storage logical.Storage) error {
	var config rootConfig

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

func (e *exoscale) LoadConfig(cfg rootConfig) error {
	exo, err := egoscale.NewClient(cfg.RootAPIKey, cfg.RootAPISecret)
	if err != nil {
		return fmt.Errorf("unable to initialize Exoscale client: %w", err)
	}

	reqEndpoint := exoapi.NewReqEndpoint(cfg.APIEnvironment, cfg.Zone)

	e.Lock()
	e.egoscaleClient = exo
	e.reqEndpoint = reqEndpoint
	e.configured = true
	e.apiKey = cfg.RootAPIKey
	e.RLocker().Unlock()

	return nil
}

// parseIAMAccessKeyResource parses a string-encoded IAM access key resource formatted such as
// DOMAIN/TYPE:NAME and deserializes it into an egoscale.IAMAccessKeyResource struct.
func parseIAMAccessKeyResource(v string) (*egoscale.IAMAccessKeyResource, error) {
	var iamAccessKeyResource egoscale.IAMAccessKeyResource

	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid format")
	}
	iamAccessKeyResource.ResourceName = parts[1]

	parts = strings.SplitN(parts[0], "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid format")
	}
	iamAccessKeyResource.Domain = parts[0]
	iamAccessKeyResource.ResourceType = parts[1]

	if iamAccessKeyResource.Domain == "" ||
		iamAccessKeyResource.ResourceType == "" ||
		iamAccessKeyResource.ResourceName == "" {
		return nil, fmt.Errorf("invalid format")
	}

	return &iamAccessKeyResource, nil
}

// V2CreateAccessKey creates a IAMv2 Access Key
func (e *exoscale) V2CreateAccessKey(ctx context.Context, roleName string, reqDisplayName string, role backendRole) (*egoscale.IAMAccessKey, error) {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return nil, errors.New("backend is not configured")
	}

	opts := make([]egoscale.CreateIAMAccessKeyOpt, 0)
	if len(role.Operations) > 0 {
		opts = append(opts, egoscale.CreateIAMAccessKeyWithOperations(role.Operations))
	}

	if len(role.Resources) > 0 {
		resources := make([]egoscale.IAMAccessKeyResource, len(role.Resources))
		for i, rs := range role.Resources {
			r, err := parseIAMAccessKeyResource(rs)
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

	iamAPIKey, err := e.CreateIAMAccessKey(
		exoapi.WithEndpoint(ctx, e.reqEndpoint),
		e.reqEndpoint.Zone(),
		fmt.Sprintf("vault-%s-%s-%d-deprecated", roleName, reqDisplayName, time.Now().UnixNano()),
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create a new API key: %w", err)
	}

	return iamAPIKey, nil
}

// V2RevokeAccessKey revokes a IAMv2 Access Key
func (e *exoscale) V2RevokeAccessKey(ctx context.Context, key string) error {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return errors.New("backend is not configured")
	}

	return e.RevokeIAMAccessKey(exoapi.WithEndpoint(ctx, e.reqEndpoint), e.reqEndpoint.Zone(), &egoscale.IAMAccessKey{Key: &key})
}

// V3CreateAPIKey creates a IAMv3 API Key
func (e *exoscale) V3CreateAPIKey(ctx context.Context, roleName string, reqDisplayName string, role backendRole) (*oapi.IamApiKeyCreated, error) {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return nil, errors.New("backend is not configured")
	}

	roleID, err := e.V3GetRoleID(ctx, role.IAMRoleName)
	if err != nil {
		return nil, err
	}

	e.CreateApiKeyWithResponse(ctx, oapi.CreateApiKeyJSONRequestBody{
		Name:   fmt.Sprintf("vault-%s-%s-%d", roleName, reqDisplayName, time.Now().UnixNano()),
		RoleId: roleID,
	})

	return nil, nil
}

// V3DeleteAPIKey deletes a IAMv3 API Key
func (e *exoscale) V3DeleteAPIKey(ctx context.Context, id string) error {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return errors.New("backend is not configured")
	}

	resp, err := e.DeleteApiKeyWithResponse(ctx, id)
	if err != nil {
		return err
	}

	if *resp.JSON200.State != oapi.OperationStateSuccess { // TODO
		return errors.New(*resp.JSON200.Message)
	}

	return nil
}

// V3GetRoleID takes a role ID or name and returns a role ID if that role exists
func (e *exoscale) V3GetRoleID(ctx context.Context, role string) (string, error) {
	e.RLock()
	defer e.RUnlock()

	if !e.configured {
		return "", errors.New("backend is not configured")
	}

	rolebyid, err := e.GetIamRoleWithResponse(ctx, role)
	if err == nil && rolebyid.JSON200 != nil {
		return *rolebyid.JSON200.Id, nil
	}

	allroles, err := e.ListIamRolesWithResponse(ctx)
	if err != nil {
		return "", err
	}

	if allroles.JSON200 != nil && allroles.JSON200.IamRoles != nil {
		for _, r := range *allroles.JSON200.IamRoles {
			if *r.Name == role {
				return *r.Id, nil
			}
		}
	}

	return "", errors.New("role not found")
}

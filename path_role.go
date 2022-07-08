package exoscale

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backendRole struct {
	Operations  []string     `json:"operations"`
	Resources   []string     `json:"resources"`
	Tags        []string     `json:"tags"`
	LeaseConfig *leaseConfig `json:"lease_config,omitempty"`
	Renewable   bool         `json:"renewable"`
}

const (
	roleStoragePathPrefix = "role/"

	configRoleName       = "name"
	configRoleOperations = "operations"
	configRoleResources  = "resources"
	configRoleTags       = "tags"
	configRoleTTL        = "ttl"
	configRoleMaxTTL     = "max_ttl"
	configRoleRenewable  = "renewable"
)

const (
	pathListRolesHelpSyn  = "List the configured backend roles"
	pathListRolesHelpDesc = `
This endpoint returns a list of the configured backend roles.
`

	pathRoleHelpSyn  = "Manage backend roles"
	pathRoleHelpDesc = `
This endpoint manages backend roles, which are used to generate Exoscale API
key secrets with Vault.

Roles are strictly Vault-local, there is no such concept in the Exoscale IAM
service: when creating a role, you can optionally specify a list of API
operations/tags that Vault-generated API keys will be restricted to when
referencing this role. If no operations/tags are specified during the role
creation, resulting API keys based on this role will be unrestricted.

Optionally, it is possible to specify lease configuration settings specific to
a role, which if set will override system or backend-level lease values.

Examples:

* A read-only role:

    vault write exoscale/role/read-only tags=read


* An object storage dedicated role restricted to the "vault-example" bucket:

    vault write exoscale/role/sos-vault-example \
        tags=sos \
        resources=sos/bucket:vault-example


Note: if the Exoscale root API key configured in the backend is itself
restricted, you will not be able to specify API operations that the root API
key is not allowed to perform. The list of available API operations is
documented on the Exoscale API website: https://api.exoscale.com/
`
)

func (b *exoscaleBackend) pathListRoles() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.listRoles},
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func (b *exoscaleBackend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			configRoleName: {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
			configRoleOperations: {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of API operations to restrict API keys to",
			},
			configRoleResources: {
				Type: framework.TypeCommaStringSlice,
				Description: "Comma-separated list of API resources to restrict API keys to " +
					" (format: DOMAIN/TYPE=NAME, e.g. \"sos/bucket:my-bucket\")",
			},
			configRoleTags: {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of API tags to restrict API keys to",
			},
			configRoleTTL: {
				Type:        framework.TypeDurationSecond,
				Description: "Duration of issued API key secrets",
			},
			configRoleMaxTTL: {
				Type:        framework.TypeDurationSecond,
				Description: `Duration after which the issued API key secrets are not allowed to be renewed`,
			},
			configRoleRenewable: {
				Type:        framework.TypeBool,
				Description: `Is the secret renewable?`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.writeRole},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.writeRole},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.readRole},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.deleteRole},
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func (b *exoscaleBackend) roleConfig(ctx context.Context, storage logical.Storage, name string) (*backendRole, error) {
	if name == "" {
		return nil, errors.New("invalid role name")
	}

	entry, err := storage.Get(ctx, roleStoragePathPrefix+name)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve role %q: %w", name, err)
	}
	if entry == nil {
		return nil, nil
	}

	role := backendRole{
		Renewable: true, // default to true for backward compatibility
	}
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (b *exoscaleBackend) listRoles(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, roleStoragePathPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *exoscaleBackend) readRole(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get(configRoleName).(string)

	role, err := b.roleConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	res := &logical.Response{
		Data: map[string]interface{}{
			configRoleOperations: role.Operations,
			configRoleResources:  role.Resources,
			configRoleTags:       role.Tags,
			configRoleRenewable:  role.Renewable,
		},
	}

	if role.LeaseConfig != nil {
		res.Data[configRoleTTL] = int64(role.LeaseConfig.TTL.Seconds())
		res.Data[configRoleMaxTTL] = int64(role.LeaseConfig.MaxTTL.Seconds())
	}

	return res, nil
}

func (b *exoscaleBackend) writeRole(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get(configRoleName).(string)

	role, err := b.roleConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = new(backendRole)
	}

	operations, ok := data.GetOk(configRoleOperations)
	if ok {
		role.Operations = operations.([]string)
	}

	resources, ok := data.GetOk(configRoleResources)
	if ok {
		for _, r := range resources.([]string) {
			if _, err := parseIAMAccessKeyResource(r); err != nil {
				return logical.ErrorResponse(fmt.Sprintf("invalid API resource %q", r)), nil
			}
		}
		role.Resources = resources.([]string)
	}

	tags, ok := data.GetOk(configRoleTags)
	if ok {
		role.Tags = tags.([]string)
	}

	role.Renewable = true // backward compatibility
	renewable, ok := data.GetOk(configRoleRenewable)
	if ok {
		role.Renewable = renewable.(bool)
	}

	ttl, hasTTL := data.GetOk(configRoleTTL)
	maxTTL, hasMaxTTL := data.GetOk(configRoleMaxTTL)
	if hasTTL || hasMaxTTL {
		if !hasTTL || !hasMaxTTL {
			return logical.ErrorResponse(fmt.Sprintf(
				`"%s" and "%s" must both be specified`,
				configRoleTTL,
				configRoleMaxTTL,
			)), nil
		}
		if ttl.(int) == 0 || maxTTL.(int) == 0 {
			return logical.ErrorResponse(fmt.Sprintf(
				`"%s" and "%s" value must be greater than 0`,
				configRoleTTL,
				configRoleMaxTTL,
			)), nil
		}

		role.LeaseConfig = &leaseConfig{
			TTL:    time.Second * time.Duration(ttl.(int)),
			MaxTTL: time.Second * time.Duration(maxTTL.(int)),
		}
	}

	entry, err := logical.StorageEntryJSON(roleStoragePathPrefix+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *exoscaleBackend) deleteRole(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	name := data.Get(configRoleName).(string)
	if err := req.Storage.Delete(ctx, roleStoragePathPrefix+name); err != nil {
		return nil, err
	}

	return nil, nil
}

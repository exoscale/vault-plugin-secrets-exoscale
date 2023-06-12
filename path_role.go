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
	// IAM V2
	Operations []string `json:"operations"`
	Resources  []string `json:"resources"`
	Tags       []string `json:"tags"`

	// IAM V3
	IAMRoleName string // could we default this to "vault-role-${VAULT_ROLE_NAME}"

	// Vault
	LeaseConfig *leaseConfig `json:"lease_config,omitempty"`
	Renewable   bool         `json:"renewable"`

	Version string
}

const (
	roleStoragePathPrefix = "role/"

	configVaultRoleName = "name"
	configRoleTTL       = "ttl"
	configRoleMaxTTL    = "max_ttl"
	configRoleRenewable = "renewable"

	// IAM v2
	configRoleOperations = "operations"
	configRoleResources  = "resources"
	configRoleTags       = "tags"

	// IAM v3
	configIAMRole = "iam-role"
)

const (
	pathListRolesHelpSyn  = "List the configured backend roles"
	pathListRolesHelpDesc = `
This endpoint returns a list of the configured backend roles.
`

	pathRoleHelpSyn  = "Manage backend roles"
	pathRoleHelpDesc = `
Manage backend roles used to generate Exoscale API keys.

This plugin currently supports both or new IAM API Keys (refered to as "v3 API key" in our API)
and our legacy IAM keys (refered to as "IAM Access Key" in our API)

IAM API Keys (recommended)
==========================

IAM Keys are created from an existing IAM Role that was created externally (terraform, CLI, Web Portal, API),
it defines what the key is able to do.

Warning: Vault Roles and Exoscale IAM roles are different things, they are not
not related with one another at all!

Fields:
	iam-role: name or id of the IAM Role
	ttl (optional): How long should this key be valid if not renewed (in seconds unless and unit is specified: "s", "m", "h")
	max_ttl (optional): Hard limit on the lifetime of the key, even if renewed (in seconds unless and unit is specified: "s", "m", "h")
	renewable (optional): allow this secret to be renewed past its ttl up to its max_ttl (default: true)

Example:
    vault write exoscale/role/example \
    	ttl=36h \
	renewable=false \
	iam-role=vault-role-example


Legacy IAM Access Keys (deprecated)
===================================

When creating a role, you can optionally specify a list of API
operations/tags that Vault-generated API keys will be restricted to when
referencing this role. If no operations/tags are specified during the role
creation, resulting API keys based on this role will be unrestricted.

Optionally, it is possible to specify lease configuration settings specific to
a role, which if set will override system or backend-level lease values.

Examples:
    vault write exoscale/role/read-only tags=read

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
		Pattern: "role/" + framework.GenericNameRegex(configVaultRoleName),
		Fields: map[string]*framework.FieldSchema{
			// Vault
			configVaultRoleName: {
				Type:        framework.TypeString,
				Description: "Name of the vault role",
				Required:    true,
			},
			configRoleTTL: {
				Type:        framework.TypeDurationSecond,
				Description: "Duration of issued API key secrets",
				Deprecated:  true,
			},
			configRoleMaxTTL: {
				Type:        framework.TypeDurationSecond,
				Description: `Duration after which the issued API key secrets are not allowed to be renewed`,
				Deprecated:  true,
			},
			configRoleRenewable: {
				Type:        framework.TypeBool,
				Description: `Is the secret renewable?`,
				Deprecated:  true,
			},

			// IAM v2
			configRoleOperations: {
				Type:        framework.TypeCommaStringSlice,
				Description: "(deprecated) Comma-separated list of API operations to restrict API keys to",
			},
			configRoleResources: {
				Type: framework.TypeCommaStringSlice,
				Description: "(deprecated) Comma-separated list of API resources to restrict API keys to " +
					" (format: DOMAIN/TYPE=NAME, e.g. \"sos/bucket:my-bucket\")",
			},
			configRoleTags: {
				Type:        framework.TypeCommaStringSlice,
				Description: "(deprecated) Comma-separated list of API tags to restrict API keys to",
			},

			// IAM v3
			configIAMRole: {
				Type: framework.TypeString,
				Description: `Name or ID of an Exoscale IAM role created externally (e.g. with terraform).
				Cannot be used in conjuction with the deprecated fields: operations, resources or tags.`,
				// When IAM v2 is phased out, it could `defaults to "vault-role-${NAME}"`
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

func (b *exoscaleBackend) getRole(ctx context.Context, storage logical.Storage, name string) (*backendRole, error) {
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
		Version:   "v2",
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
	name := data.Get(configVaultRoleName).(string)

	role, err := b.getRole(ctx, req.Storage, name)
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

	// TODO: if v2
	res.Data["warning"] = "Legacy IAM Access Keys are deprecated, plase switch to the new IAM API Keys and Roles"

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
	name := data.Get(configVaultRoleName).(string)

	role, err := b.getRole(ctx, req.Storage, name)
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
			return logical.ErrorResponse(fmt.Sprintf(`"%s" and "%s" must both be specified`,
				configRoleTTL, configRoleMaxTTL)), nil
		}
		if ttl.(int) == 0 || maxTTL.(int) == 0 {
			return logical.ErrorResponse(fmt.Sprintf(`"%s" and "%s" value must be greater than 0`,
				configRoleTTL, configRoleMaxTTL)), nil
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
	name := data.Get(configVaultRoleName).(string)
	if err := req.Storage.Delete(ctx, roleStoragePathPrefix+name); err != nil {
		return nil, err
	}

	return nil, nil
}

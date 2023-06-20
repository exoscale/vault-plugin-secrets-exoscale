package exoscale

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type Role struct {
	// IAM V2
	Operations []string `json:"operations,omitempty"`
	Resources  []string `json:"resources,omitempty"`
	Tags       []string `json:"tags,omitempty"`

	// IAM V3
	IAMRoleID   string `json:"iam_role_id,omitempty"`
	IAMRoleName string `json:"iam_role_name,omitempty"`

	// Lease
	Renewable   bool          `json:"renewable,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
	MaxTTL      time.Duration `json:"max_ttl,omitempty"`
	LeaseConfig *leaseConfig  `json:"lease_config,omitempty"` // deprecated

	Version string `json:"version,omitempty"`
}

func (role *Role) fromFieldData(data *framework.FieldData) error {
	// v2
	if o, ok := data.GetOk(configRoleOperations); ok {
		role.Operations = o.([]string)
	}

	if t, ok := data.GetOk(configRoleTags); ok {
		role.Tags = t.([]string)
	}

	if r, ok := data.GetOk(configRoleResources); ok {
		role.Resources = r.([]string)
	}

	var resErrs error
	for _, r := range role.Resources {
		_, err := V2ParseIAMResource(r)
		resErrs = errors.Join(resErrs, err)
	}
	if resErrs != nil {
		return fmt.Errorf("invalid API resource(s): %w", resErrs)
	}

	// v3
	role.IAMRoleID = data.Get(configIAMRole).(string)

	// lease
	if r, ok := data.GetOk(configRoleRenewable); ok {
		role.Renewable = r.(bool)
	}

	if t, ok := data.GetOk(configRoleTTL); ok {
		role.TTL = time.Duration(t.(int)) * time.Second
	}

	if mt, ok := data.GetOk(configRoleMaxTTL); ok {
		role.MaxTTL = time.Duration(mt.(int)) * time.Second
	}

	if role.MaxTTL != 0 && role.TTL == 0 {
		return errors.New(`ttl must be sepcified if max_ttl is specified`)
	}

	// version
	v2FieldSet := (role.Operations != nil || role.Resources != nil || role.Tags != nil)
	v3FieldSet := role.IAMRoleID != ""
	if v2FieldSet && v3FieldSet {
		return errors.New("iam-role cannot be used in conjuction with the deprecated fields: operations, resources or tags.")
	} else if v3FieldSet {
		role.Version = "v3"
	} else {
		role.Version = "v2" // nothing set means v2 unrestricted
	}

	return nil
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

This plugin currently supports both our new IAM API Keys (refered to as "v3 API key" in our API)
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
`
)

func (b *exoscaleBackend) pathRole() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex(configVaultRoleName),
			Fields: map[string]*framework.FieldSchema{
				// Vault
				configVaultRoleName: {
					Type:        framework.TypeString,
					Description: "Name of the vault role",
					Required:    true,
				},
				configRoleTTL: {
					Type: framework.TypeDurationSecond,
					Description: `Duration of issued API key secrets.
				If not set or set to 0, it will use backend default (config/lease)`,
				},
				configRoleMaxTTL: {
					Type: framework.TypeDurationSecond,
					Description: `Duration after which the issued API key secrets are not allowed to be renewed.
				If not set or set to 0, it will use backend default (config/lease)`,
				},
				configRoleRenewable: {
					Type:        framework.TypeBool,
					Description: `Is the secret renewable?`,
					Default:     true,
				},

				// IAM v2
				configRoleOperations: {
					Type:        framework.TypeCommaStringSlice,
					Description: "(deprecated) Comma-separated list of API operations to restrict API keys to",
					Deprecated:  true,
				},
				configRoleResources: {
					Type: framework.TypeCommaStringSlice,
					Description: "(deprecated) Comma-separated list of API resources to restrict API keys to " +
						" (format: DOMAIN/TYPE=NAME, e.g. \"sos/bucket:my-bucket\")",
					Deprecated: true,
				},
				configRoleTags: {
					Type:        framework.TypeCommaStringSlice,
					Description: "(deprecated) Comma-separated list of API tags to restrict API keys to",
					Deprecated:  true,
				},

				// IAM v3
				configIAMRole: {
					Type: framework.TypeString,
					Description: `Name or ID of an Exoscale IAM role created externally (e.g. with terraform).
				Cannot be used in conjuction with the deprecated fields: operations, resources or tags.`,
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
		},
		{
			Pattern: "role/?$",

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.listRoles},
			},

			HelpSynopsis:    pathListRolesHelpSyn,
			HelpDescription: pathListRolesHelpDesc,
		},
	}
}

func getRole(ctx context.Context, storage logical.Storage, name string) (*Role, error) {
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

	// default values for backward compatibility
	role := Role{
		Renewable: true,
		Version:   "v2",
	}
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	// backward compatibility
	if role.LeaseConfig != nil {
		role.TTL = role.LeaseConfig.TTL
		role.MaxTTL = role.LeaseConfig.MaxTTL
		role.LeaseConfig = nil
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
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	var res *logical.Response
	if role.Version == "v2" {
		res = &logical.Response{
			Data: map[string]interface{}{
				configRoleOperations: role.Operations,
				configRoleResources:  role.Resources,
				configRoleTags:       role.Tags,
			},
		}
		res.AddWarning("Legacy IAM Access Keys are deprecated, plase switch to the new IAM API Keys and Roles")

	} else {
		res = &logical.Response{
			Data: map[string]interface{}{
				"iam-role-id":   role.IAMRoleID,
				"iam-role-name": role.IAMRoleName,
			},
		}
	}

	if role.TTL != 0 {
		res.Data[configRoleTTL] = role.TTL.Seconds()
	}
	if role.MaxTTL != 0 {
		res.Data[configRoleMaxTTL] = role.MaxTTL.Seconds()
	}
	res.Data[configRoleRenewable] = role.Renewable

	return res, nil
}

func (b *exoscaleBackend) writeRole(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get(configVaultRoleName).(string)
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &Role{Renewable: true}
	}

	if err := role.fromFieldData(data); err != nil {
		return nil, err
	}

	res := &logical.Response{}

	if role.Version == "v3" {
		mountMaxTTL := b.System().MaxLeaseTTL()
		if role.MaxTTL > mountMaxTTL {
			res.AddWarning(fmt.Sprintf("MaxTTL %q is higher than the effective MaxTTL of %q for this mount", role.MaxTTL, mountMaxTTL))
		}
		if role.TTL > role.MaxTTL || role.TTL > mountMaxTTL {
			res.AddWarning(fmt.Sprintf("TTL %q is higher than the effective MaxTTL for this mount", role.TTL))
		}

		iamrole, err := b.exo.V3GetRole(ctx, role.IAMRoleID)
		if err != nil {
			return nil, err
		}
		role.IAMRoleID = *iamrole.Id
		role.IAMRoleName = *iamrole.Name
	}

	entry, err := logical.StorageEntryJSON(roleStoragePathPrefix+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return res, nil
}

func (b *exoscaleBackend) deleteRole(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	name := data.Get(configVaultRoleName).(string)
	if err := req.Storage.Delete(ctx, roleStoragePathPrefix+name); err != nil {
		return nil, err
	}

	return nil, nil
}

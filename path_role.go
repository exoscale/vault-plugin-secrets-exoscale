package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

const roleStoragePathPrefix = "role/"

var pathListRolesHelpSyn = "List the configured backend roles"
var pathListRolesHelpDesc = `
This endpoint returns a list of the configured backend roles.
`

var pathRoleHelpSyn = "Manage backend roles"
var pathRoleHelpDesc = `
This endpoint manages backend roles, which are used to generate Exoscale API
key secrets with Vault.

Roles are strictly Vault-local, there is no such concept in the Exoscale IAM
service: when creating a role, you can optionally specify a list of API
operations that Vault-generated API keys will be restricted to when
referencing this role. If no operations are specified during the role
creation, resulting API keys based on this role will be unrestricted.

Note: if the Exoscale root API key configured in the backend is itself
restricted, you will not be able to specify API operations that the root API
key is not allowed to perform. The list of available API operations is
documented on the Exoscale API website: https://api.exoscale.com/
`

func pathListRoles(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.listRoles},
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRole(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"operations": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of API operations to restrict API keys to",
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

func (b *exoscaleBackend) roleConfig(ctx context.Context, storage logical.Storage, name string) (*roleConfig, error) {
	var role roleConfig

	if name == "" {
		return nil, errors.New("invalid role name")
	}

	entry, err := storage.Get(ctx, roleStoragePathPrefix+name)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving role %q", name)
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (b *exoscaleBackend) listRoles(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, roleStoragePathPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *exoscaleBackend) readRole(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := b.roleConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"operations": role.Operations,
		},
	}, nil
}

func (b *exoscaleBackend) writeRole(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := b.roleConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = new(roleConfig)
	}

	operations, ok := data.GetOk("operations")
	if ok {
		role.Operations = operations.([]string)
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
	name := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, roleStoragePathPrefix+name); err != nil {
		return nil, err
	}

	return nil, nil
}

type roleConfig struct {
	Operations []string `json:"operations"`
}

package exoscale

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const SecretTypeAPIKey = "apikey"

func (b *exoscaleBackend) secretAPIKey() *framework.Secret {
	return &framework.Secret{
		Type: SecretTypeAPIKey,
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "API key name",
			},
			"api_key": {
				Type:        framework.TypeString,
				Description: "API key",
			},
			"api_secret": {
				Type:        framework.TypeString,
				Description: "API secret",
			},
		},

		Renew:  b.secretAPIKeyRenew,
		Revoke: b.secretAPIKeyRevoke,
	}
}

func (b *exoscaleBackend) secretAPIKeyRenew(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	roleName, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing the role field in its internal data")
	}

	role, err := b.getRole(ctx, req.Storage, roleName.(string))
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q not found", roleName)), nil
	}

	if !role.Renewable {
		return logical.ErrorResponse(fmt.Sprintf("secret is not renewable role=%q", roleName)), nil
	}

	iamKey, ok := req.Secret.InternalData["api_key"]
	if !ok {
		return nil, errors.New("'api_key' is missing from the secret's internal data")
	}

	iamName, ok := req.Secret.InternalData["name"]
	if !ok {
		return nil, errors.New("'name' is missing from the secret's internal data")
	}

	var leaseCfg leaseConfig

	if role.LeaseConfig != nil {
		leaseCfg = *role.LeaseConfig
	} else {
		lc, err := b.leaseConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		if lc != nil {
			leaseCfg = *lc
		}
	}

	res := &logical.Response{Secret: req.Secret}
	res.Secret.MaxTTL = leaseCfg.MaxTTL

	ttl, _, err := framework.CalculateTTL(b.System(), 0, leaseCfg.TTL, 0, 0, leaseCfg.MaxTTL, req.Secret.IssueTime)
	if err != nil {
		return nil, err
	}

	// Vault agent calculates a grace period of 10 to 20% of the lease TTL,
	// once we enter the grace period, the agent stops renewing the lease
	// and fetches a new one. This gives the workload time to complete
	// ongoing operations before loading the new secret.

	// After each renew, if the lease was extended, vault agent will recalculate
	// the grace period based on the new TTL. If the new TTL is above the Max TTL,
	// the value is capped, reducing the grace period to an unpredictable amount
	// of time.

	// To make sure it will calculate the refresh grace period based
	// on a full TTL value, we extend the lease only if the TTL is
	// not capped by max_ttl
	if ttl == leaseCfg.TTL {
		res.Secret.TTL = ttl
		res.Secret.InternalData["expireTime"] = time.Now().Add(res.Secret.TTL)
		b.Logger().Info("Renewing",
			"ttl", fmt.Sprint(res.Secret.TTL), "role", roleName,
			"iam_key", iamKey,
			"iam_name", iamName)
	} else {
		rawExpireTime, ok := req.Secret.InternalData["expireTime"]
		if !ok {
			return nil, fmt.Errorf("expireTime missing from secret's InternalData")
		}

		expireTime, err := time.Parse(time.RFC3339, rawExpireTime.(string))
		if err != nil {
			return nil, fmt.Errorf("can't parse expireTime from secret's InternalData")
		}

		res.Secret.TTL = time.Until(expireTime)
		b.Logger().Info("Not renewing because ttl would be capped by max_ttl ",
			"ttl", fmt.Sprint(res.Secret.TTL),
			"capped_ttl", fmt.Sprint(ttl),
			"role", roleName,
			"iam_key", iamKey,
			"iam_name", iamName)
	}

	return res, nil
}

func (b *exoscaleBackend) secretAPIKeyRevoke(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	key, ok := req.Secret.InternalData["api_key"]
	if !ok {
		return nil, errors.New("API key is missing from the secret")
	}

	err := b.exo.V2RevokeAccessKey(ctx, key.(string))
	if err != nil && strings.HasSuffix(err.Error(), ": resource not found") {
		b.Logger().Warn("IAM key deosn't exist anymore, cleaning up secret", "key", key, "lease_id", req.Secret.LeaseID)
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to revoke the API key: %w", err)
	}

	b.Logger().Info("IAM key revoked", "key", key.(string), "lease_id", req.Secret.LeaseID)
	return nil, nil
}

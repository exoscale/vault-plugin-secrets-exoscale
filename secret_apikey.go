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
	iamKey, ok := req.Secret.InternalData["api_key"]
	if !ok {
		return nil, errors.New("'api_key' is missing from the secret's internal data")
	}

	iamName, ok := req.Secret.InternalData["name"]
	if !ok {
		return nil, errors.New("'name' is missing from the secret's internal data")
	}

	res := &logical.Response{Secret: req.Secret}

	ttl, _, err := framework.CalculateTTL(b.System(), 0, req.Secret.TTL, 0, 0, req.Secret.MaxTTL, req.Secret.IssueTime)
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
	if ttl == req.Secret.TTL {
		res.Secret.TTL = ttl
		res.Secret.InternalData["expireTime"] = time.Now().Add(res.Secret.TTL)
		b.Logger().Info("Renewing",
			"ttl", fmt.Sprint(res.Secret.TTL),
			"role", req.Secret.InternalData["role"],
			"test", req.Secret.InternalData["roleodok,feorfreon"],
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
			"role", req.Secret.InternalData["role"],
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

	version := "v2"
	if v, ok := req.Secret.InternalData["version"]; ok {
		version = v.(string)
	}

	var err error
	if version == "v2" {
		err = b.exo.V2RevokeAccessKey(ctx, key.(string))
	} else {
		err = b.exo.V3DeleteAPIKey(ctx, key.(string))
	}

	if err != nil && strings.HasSuffix(err.Error(), ": resource not found") {
		b.Logger().Warn("IAM key deosn't exist anymore, cleaning up secret", "key", key, "lease_id", req.Secret.LeaseID)
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to revoke the API key: %w", err)
	}

	b.Logger().Info("IAM key revoked", "key", key.(string), "lease_id", req.Secret.LeaseID)
	return nil, nil
}

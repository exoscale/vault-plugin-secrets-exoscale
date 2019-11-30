// +build testacc

package exoscale

import (
	"context"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func (t *backendTestSuite) TestSecretAPIKeyRevoke() {
	backend, storage, err := testAccBackend(t.T())
	if err != nil {
		t.FailNow("unable to initialize backend", err)
	}

	entry, err := logical.StorageEntryJSON(roleStoragePathPrefix+testRoleName, roleConfig{})
	if err != nil {
		t.FailNow("unable to JSON-encode entry", err)
	}

	if err := storage.Put(context.Background(), entry); err != nil {
		t.FailNow("unable to store entry", err)
	}

	vaultRes, err := backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      apiKeyPathPrefix + testRoleName,
	})
	if err != nil {
		t.FailNow("request failed", err)
	}

	iamRes, err := backend.exo.RequestWithContext(context.Background(), egoscale.GetAPIKey{
		Key: vaultRes.Data["api_key"].(string),
	})
	if err != nil {
		t.FailNow("unable to retrieve API key from Exoscale API", err)
	}
	actualAPIKey := iamRes.(*egoscale.APIKey)

	require.Equal(t.T(), vaultRes.Data["api_key"].(string), actualAPIKey.Key)

	_, err = backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.RevokeOperation,
		Path:      vaultRes.Secret.LeaseID,
		Secret:    vaultRes.Secret,
	})
	if err != nil {
		t.FailNow("request failed", err)
	}

	_, err = backend.exo.RequestWithContext(context.Background(), egoscale.GetAPIKey{
		Key: vaultRes.Data["api_key"].(string),
	})
	require.Equal(t.T(), egoscale.ErrorCode(404), err.(*egoscale.ErrorResponse).ErrorCode)
}

// +build testacc

package exoscale

import (
	"context"
	"strings"
	"time"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func (t *backendTestSuite) TestPathAPIKey() {
	var (
		testLeaseTTL    = 3 * time.Second
		testLeaseMaxTTL = 1 * time.Hour
	)

	backend, storage, err := testAccBackend(t.T())
	if err != nil {
		t.FailNow("unable to initialize backend", err)
	}

	entry, err := logical.StorageEntryJSON(roleStoragePathPrefix+testRoleName, roleConfig{
		Operations: testRoleOperations,
	})
	if err != nil {
		t.FailNow("unable to JSON-encode entry", err)
	}

	if err := storage.Put(context.Background(), entry); err != nil {
		t.FailNow("unable to store entry", err)
	}

	entry, err = logical.StorageEntryJSON(configLeaseStoragePath, leaseConfig{
		TTL:    testLeaseTTL,
		MaxTTL: testLeaseMaxTTL,
	})
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
	defer func() {
		if _, err := backend.exo.RequestWithContext(context.Background(), &egoscale.RevokeAPIKey{
			Key: actualAPIKey.Key,
		}); err != nil {
			t.FailNow("unable to revoke the API key", err)
		}
	}()

	require.True(t.T(), strings.HasPrefix(vaultRes.Data["name"].(string), "vault-"+testRoleName))
	require.Equal(t.T(), vaultRes.Data["api_key"].(string), actualAPIKey.Key)
	require.NotEmpty(t.T(), vaultRes.Data["api_secret"].(string))
	require.ElementsMatch(t.T(), testRoleOperations, actualAPIKey.Operations)
	require.Equal(t.T(), testLeaseTTL, vaultRes.Secret.TTL)
	require.Equal(t.T(), testLeaseMaxTTL, vaultRes.Secret.MaxTTL)
}

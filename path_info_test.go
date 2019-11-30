package exoscale

import (
	"context"

	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func (t *backendTestSuite) TestPathInfoRead() {
	backend, storage := testBackend(t.T())

	res, err := backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "info",
	})
	if err != nil {
		t.FailNow("request failed", err)
	}

	require.Equal(t.T(), version.Version, res.Data["version"].(string))
	require.Equal(t.T(), version.Commit, res.Data["commit"].(string))
}

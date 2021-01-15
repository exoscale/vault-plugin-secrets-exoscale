package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
)

func (ts *backendTestSuite) TestPathInfoRead() {
	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      "info",
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(version.Version, res.Data["version"].(string))
	ts.Require().Equal(version.Commit, res.Data["commit"].(string))
}

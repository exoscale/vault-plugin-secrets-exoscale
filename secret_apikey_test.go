package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"

	egoscale "github.com/exoscale/egoscale/v2"
)

func (ts *testSuite) TestSecretAPIKeyRevoke() {
	var revoked bool

	ts.storeEntry(roleStoragePathPrefix+testRoleName, Role{
		Operations: testRoleOperations,
		Tags:       testRoleTags,
	})

	testSecret := &logical.Secret{
		InternalData: map[string]interface{}{
			"api_key":     testIAMAccessKeyKey,
			"secret_type": SecretTypeAPIKey,
		},
		LeaseID: ts.randomID(),
	}

	ts.backend.(*exoscaleBackend).exo.egoscaleClient.(*mockEgoscaleClient).
		On("RevokeIAMAccessKey", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ts.Require().Equal(&egoscale.IAMAccessKey{Key: &testIAMAccessKeyKey}, args.Get(2))
			revoked = true
		}).
		Return(nil)

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.RevokeOperation,
		Path:      testSecret.LeaseID,
		Secret:    testSecret,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}
	ts.Require().NoError(err)
	ts.Require().True(revoked)
}

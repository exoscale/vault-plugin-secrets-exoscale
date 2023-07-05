package exoscale

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/exoscale/egoscale/v2/oapi"
)

func (ts *testSuite) TestSecretAPIKeyV2Revoke() {
	var revoked bool

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

func (ts *testSuite) TestSecretAPIKeyV3Revoke() {
	var revoked bool

	ts.storeEntry(roleStoragePathPrefix+testRoleName, Role{
		IAMRoleID:   ts.randomID(),
		IAMRoleName: "blabla",
		Version:     "v3",
	})

	testSecret := &logical.Secret{
		InternalData: map[string]interface{}{
			"api_key":     testIAMAccessKeyKey,
			"secret_type": SecretTypeAPIKey,
			"version":     "v3",
		},
		LeaseID: ts.randomID(),
	}

	state := oapi.OperationStateSuccess
	ts.backend.(*exoscaleBackend).exo.egoscaleClient.(*mockEgoscaleClient).
		On("DeleteApiKeyWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			// ts.Require().Equal(testIAMAccessKeyKey, args.Get(1))
			revoked = true
		}).
		Return(&oapi.DeleteApiKeyResponse{JSON200: &oapi.Operation{State: &state}}, nil)

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

func (ts *testSuite) TestSecretAPIKeyV2Renew() {
	testSecret := &logical.Secret{
		InternalData: map[string]interface{}{
			"api_key":     testIAMAccessKeyKey,
			"secret_type": SecretTypeAPIKey,
			"role":        "my-renew-rol",
			"expireTime":  time.Now().Add(1 * time.Minute).Format(time.RFC3339),
			"name":        "vault-blabla",
		},
		LeaseID: ts.randomID(),
		LeaseOptions: logical.LeaseOptions{
			TTL: 3 * time.Minute,
		},
	}

	resp, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.RenewOperation,
		Path:      testSecret.LeaseID,
		Secret:    testSecret,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}
	ts.Require().NoError(err)
	ts.Require().Equal(3*time.Minute, resp.Secret.TTL)
}

func (ts *testSuite) TestSecretAPIKeyV3Renew() {
	testSecret := &logical.Secret{
		InternalData: map[string]interface{}{
			"api_key":     testIAMAccessKeyKey,
			"secret_type": SecretTypeAPIKey,
			"role":        "my-renew-rol",
			"expireTime":  time.Now().Add(1 * time.Minute).Format(time.RFC3339),
			"name":        "vault-blabla",
			"version":     "v3",
		},
		LeaseID: ts.randomID(),
		LeaseOptions: logical.LeaseOptions{
			TTL: 4 * time.Minute,
		},
	}

	resp, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.RenewOperation,
		Path:      testSecret.LeaseID,
		Secret:    testSecret,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}
	ts.Require().NoError(err)
	ts.Require().Equal(4*time.Minute, resp.Secret.TTL)
}

func (ts *testSuite) TestSecretAPIKeyV3RenewAboveExplicitMaxTTL() {
	testSecret := &logical.Secret{
		InternalData: map[string]interface{}{
			"api_key":     testIAMAccessKeyKey,
			"secret_type": SecretTypeAPIKey,
			"role":        "my-renew-rol",
			"expireTime":  time.Now().Add(1 * time.Minute).Format(time.RFC3339),
			"name":        "vault-blabla",
			"version":     "v3",
		},
		LeaseID: ts.randomID(),
		LeaseOptions: logical.LeaseOptions{
			TTL:       4 * time.Minute,
			MaxTTL:    5 * time.Minute,
			IssueTime: time.Now().Add(-3 * time.Minute),
		},
	}

	resp, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.RenewOperation,
		Path:      testSecret.LeaseID,
		Secret:    testSecret,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}
	ts.Require().NoError(err)
	ts.Require().LessOrEqual(resp.Secret.TTL, 1*time.Minute)
}

func (ts *testSuite) TestSecretAPIKeyV3RenewAboveSystemMaxTTL() {
	testSecret := &logical.Secret{
		InternalData: map[string]interface{}{
			"api_key":     testIAMAccessKeyKey,
			"secret_type": SecretTypeAPIKey,
			"role":        "my-renew-rol",
			"expireTime":  time.Now().Add(1 * time.Minute).Format(time.RFC3339),
			"name":        "vault-blabla",
			"version":     "v3",
		},
		LeaseID: ts.randomID(),
		LeaseOptions: logical.LeaseOptions{
			TTL:       8 * time.Hour,
			IssueTime: time.Now().Add(-47 * time.Hour),
		},
	}

	resp, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.RenewOperation,
		Path:      testSecret.LeaseID,
		Secret:    testSecret,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}
	ts.Require().NoError(err)
	ts.Require().LessOrEqual(resp.Secret.TTL, 1*time.Minute)
}

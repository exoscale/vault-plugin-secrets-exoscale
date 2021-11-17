package exoscale

import (
	"context"
	"fmt"
	"strings"
	"time"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/exoscale/egoscale/v2/oapi"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
)

var (
	testIAMAccessKeyNamePrefix = fmt.Sprintf("vault-%s-", testRoleName)
	testIAMAccessKeyKey        = "EXOxxxxxxxxxxxxxxxxxxxxxxxx"
	testIAMAccessKeySecret     = "yyyyyyyyy-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	testIAMAccessKeyType       = string(oapi.AccessKeyTypeRestricted)
	testIAMAccessKeyVersion    = string(oapi.AccessKeyVersionV2)
	created                    bool
)

func (ts *testSuite) TestPathAPIKey() {
	var (
		actualIAMAccessKeyName string
		testLeaseTTL           = 3 * time.Second
		testLeaseMaxTTL        = 1 * time.Hour
	)

	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Operations: testRoleOperations,
		Tags:       testRoleTags,
	})
	ts.storeEntry(configLeaseStoragePath, leaseConfig{
		TTL:    testLeaseTTL,
		MaxTTL: testLeaseMaxTTL,
	})

	ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).
		On("CreateIAMAccessKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			actualIAMAccessKeyName = args.Get(2).(string)

			ts.Require().True(strings.HasPrefix(actualIAMAccessKeyName, testIAMAccessKeyNamePrefix))
			ts.Require().Len(args.Get(3).([]egoscale.CreateIAMAccessKeyOpt), 2)
			created = true
		}).
		Return(&egoscale.IAMAccessKey{
			Key:        &testIAMAccessKeyKey,
			Name:       &actualIAMAccessKeyName,
			Operations: &testRoleOperations,
			Secret:     &testIAMAccessKeySecret,
			Tags:       &testRoleTags,
			Type:       &testIAMAccessKeyType,
			Version:    &testIAMAccessKeyVersion,
		}, nil)

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:     ts.storage,
		Operation:   logical.ReadOperation,
		Path:        apiKeyPathPrefix + testRoleName,
		DisplayName: "test",
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(actualIAMAccessKeyName, res.Data["name"])
	ts.Require().Equal(testIAMAccessKeyKey, res.Data["api_key"])
	ts.Require().Equal(testIAMAccessKeySecret, res.Data["api_secret"])
	ts.Require().Equal(testIAMAccessKeyKey, res.Secret.InternalData["api_key"])
	ts.Require().Equal(testLeaseTTL, res.Secret.TTL)
	ts.Require().Equal(testLeaseMaxTTL, res.Secret.MaxTTL)
	ts.Require().True(created)
}

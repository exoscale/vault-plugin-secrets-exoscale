package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testConfigAPIEndpoint   = defaultAPIEndpoint
	testConfigRootAPIKey    = "EXOabcdef0123456789abcdef01"
	testConfigRootAPISecret = "ABCDEFGHIJKLMNOPRQSTUVWXYZ0123456789abcdefg"
)

func (ts *backendTestSuite) TestPathConfigRootWriteWithMissingAPICredentials() {
	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      configRootStoragePath,
	})

	ts.Require().EqualError(err, errMissingAPICredentials.Error())
}

func (ts *backendTestSuite) TestPathConfigRootWrite() {
	var actualBackendConfig backendConfig

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      configRootStoragePath,
		Data: map[string]interface{}{
			configKeyAPIEndpoint:   testConfigAPIEndpoint,
			configKeyRootAPIKey:    testConfigRootAPIKey,
			configKeyRootAPISecret: testConfigRootAPISecret,
		},
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	entry, err := ts.storage.Get(context.Background(), configRootStoragePath)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	if err := entry.DecodeJSON(&actualBackendConfig); err != nil {
		ts.FailNow("unable to JSON-decode entry", err)
	}

	ts.Require().Equal(backendConfig{
		APIEndpoint:   testConfigAPIEndpoint,
		RootAPIKey:    testConfigRootAPIKey,
		RootAPISecret: testConfigRootAPISecret,
	}, actualBackendConfig)
}

func (ts *backendTestSuite) TestPathConfigRootRead() {
	ts.storeEntry(configRootStoragePath, backendConfig{
		APIEndpoint:   testConfigAPIEndpoint,
		RootAPIKey:    testConfigRootAPIKey,
		RootAPISecret: testConfigRootAPISecret,
	})

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      configRootStoragePath,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(testConfigAPIEndpoint, res.Data["api_endpoint"].(string))
	ts.Require().Equal(testConfigRootAPIKey, res.Data["root_api_key"].(string))
	ts.Require().Equal(testConfigRootAPISecret, res.Data["root_api_secret"].(string))
}

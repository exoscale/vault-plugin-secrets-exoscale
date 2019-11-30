package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

var (
	testConfigAPIEndpoint   = defaultAPIEndpoint
	testConfigRootAPIKey    = "EXOabcdef0123456789abcdef01"
	testConfigRootAPISecret = "ABCDEFGHIJKLMNOPRQSTUVWXYZ0123456789abcdefg"
)

func (t *backendTestSuite) TestPathConfigRootWriteWithMissingAPICredentials() {
	backend, storage := testBackend(t.T())

	_, err := backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      configRootStoragePath,
	})

	require.EqualError(t.T(), err, errMissingAPICredentials.Error())
}

func (t *backendTestSuite) TestPathConfigRootWrite() {
	var actualBackendConfig backendConfig

	backend, storage := testBackend(t.T())

	_, err := backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      configRootStoragePath,
		Data: map[string]interface{}{
			"api_endpoint":    testConfigAPIEndpoint,
			"root_api_key":    testConfigRootAPIKey,
			"root_api_secret": testConfigRootAPISecret,
		},
	})
	if err != nil {
		t.FailNow("request failed", err)
	}

	entry, err := storage.Get(context.Background(), configRootStoragePath)
	if err != nil {
		t.FailNow("unable to retrieve entry from storage", err)
	}
	if err := entry.DecodeJSON(&actualBackendConfig); err != nil {
		t.FailNow("unable to JSON-decode entry", err)
	}

	require.Equal(t.T(), backendConfig{
		APIEndpoint:   testConfigAPIEndpoint,
		RootAPIKey:    testConfigRootAPIKey,
		RootAPISecret: testConfigRootAPISecret,
	}, actualBackendConfig)
}

func (t *backendTestSuite) TestPathConfigRootRead() {
	backend, storage := testBackend(t.T())

	entry, err := logical.StorageEntryJSON(configRootStoragePath, backendConfig{
		APIEndpoint:   testConfigAPIEndpoint,
		RootAPIKey:    testConfigRootAPIKey,
		RootAPISecret: testConfigRootAPISecret,
	})
	if err != nil {
		t.FailNow("unable to JSON-encode entry", err)
	}

	if err := storage.Put(context.Background(), entry); err != nil {
		t.FailNow("unable to store entry", err)
	}

	res, err := backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      configRootStoragePath,
	})
	if err != nil {
		t.FailNow("request failed", err)
	}

	require.Equal(t.T(), testConfigAPIEndpoint, res.Data["api_endpoint"].(string))
	require.Equal(t.T(), testConfigRootAPIKey, res.Data["root_api_key"].(string))
	require.Equal(t.T(), testConfigRootAPISecret, res.Data["root_api_secret"].(string))
}

package exoscale

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	testConfigAPIEnvironment = "testapi"
	testConfigRootAPIKey     = "EXOabcdef0123456789abcdef01"
	testConfigRootAPISecret  = "ABCDEFGHIJKLMNOPRQSTUVWXYZ0123456789abcdefg"
	testConfigZone           = "de-fra-1"
)

func (ts *testSuite) TestPathConfigRootRead() {
	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      configRootStoragePath,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(map[string]interface{}{
		"api_environment":     "api",
		"root_api_key":        "EXO0000",
		"root_api_secret":     "xxxxxxxx",
		"api_key_name_prefix": "",
		"zone":                "ch-gva-2",
	}, res.Data)
}

func (ts *testSuite) TestPathConfigRootWrite() {
	tests := []struct {
		name     string
		data     map[string]interface{}
		storage  logical.Storage
		expected ExoscaleConfig
		wantErr  error
	}{
		{
			name:    "missing API credentials",
			data:    map[string]interface{}{},
			wantErr: errMissingAPICredentials,
		},
		{
			name: "minimal",
			data: map[string]interface{}{
				configRootAPIKey:    testConfigRootAPIKey,
				configRootAPISecret: testConfigRootAPISecret,
			},
			expected: ExoscaleConfig{
				APIEnvironment: "api",
				RootAPIKey:     testConfigRootAPIKey,
				RootAPISecret:  testConfigRootAPISecret,
				Zone:           "ch-gva-2",
			},
		},
		{
			name: "full",
			data: map[string]interface{}{
				configAPIEnvironment:   testConfigAPIEnvironment,
				configRootAPIKey:       testConfigRootAPIKey,
				configRootAPISecret:    testConfigRootAPISecret,
				configAPIKeyNamePrefix: "toto",
				configZone:             testConfigZone,
			},
			expected: ExoscaleConfig{
				APIEnvironment:   testConfigAPIEnvironment,
				RootAPIKey:       testConfigRootAPIKey,
				RootAPISecret:    testConfigRootAPISecret,
				Zone:             testConfigZone,
				APIKeyNamePrefix: "toto",
			},
		},
	}

	for _, tt := range tests {
		ts.T().Run(tt.name, func(t *testing.T) {
			var actualBackendConfig ExoscaleConfig
			tt.storage = &logical.InmemStorage{}

			_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
				Storage:   tt.storage,
				Operation: logical.CreateOperation,
				Path:      configRootStoragePath,
				Data:      tt.data,
			})
			if err != tt.wantErr {
				t.Errorf("pathConfigWrite() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				entry, err := tt.storage.Get(context.Background(), configRootStoragePath)
				if err != nil {
					ts.FailNow("unable to retrieve entry from storage", err)
				}
				if err := entry.DecodeJSON(&actualBackendConfig); err != nil {
					ts.FailNow("unable to JSON-decode entry", err)
				}

				ts.Require().Equal(tt.expected, actualBackendConfig)
			}
		})
	}
}

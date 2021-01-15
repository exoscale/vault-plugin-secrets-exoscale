package exoscale

import (
	"context"
	"testing"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/suite"
)

type backendTestSuite struct {
	backend logical.Backend
	storage logical.Storage

	suite.Suite
}

func (ts *backendTestSuite) storeEntry(k string, v interface{}) {
	entry, err := logical.StorageEntryJSON(k, v)
	if err != nil {
		ts.FailNow("unable to JSON-encode entry", err)
	}

	if err := ts.storage.Put(context.Background(), entry); err != nil {
		ts.FailNow("unable to store entry", err)
	}
}

func (ts *backendTestSuite) SetupTest() {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	backendConfigEntry, err := logical.StorageEntryJSON(configRootStoragePath, backendConfig{
		APIEndpoint:   testConfigAPIEndpoint,
		RootAPIKey:    testConfigRootAPIKey,
		RootAPISecret: testConfigRootAPISecret,
	})
	if err != nil {
		ts.FailNow("unable to JSON-encode backend config entry", err)
	}
	if err := config.StorageView.Put(context.Background(), backendConfigEntry); err != nil {
		ts.FailNow("unable to store backend config entry", err)
	}

	backend, err := Factory(context.Background(), config)
	if err != nil {
		ts.T().Fatal(err)
	}

	exo := egoscale.NewClient(
		testConfigAPIEndpoint,
		testConfigRootAPIKey,
		testConfigRootAPISecret)

	httpmock.ActivateNonDefault(exo.HTTPClient)

	backend.(*exoscaleBackend).exo = exo

	ts.backend = backend
	ts.storage = config.StorageView
}

func (ts *backendTestSuite) TearDownTest() {
	ts.backend = nil
	ts.storage = nil

	httpmock.DeactivateAndReset()
}

func TestSuite(t *testing.T) {
	suite.Run(t, new(backendTestSuite))
}

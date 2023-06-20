package exoscale

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/suite"
)

type testSuite struct {
	suite.Suite

	backend logical.Backend
	storage logical.Storage
}

func (ts *testSuite) storeEntry(k string, v interface{}) {
	entry, err := logical.StorageEntryJSON(k, v)
	if err != nil {
		ts.FailNow("unable to JSON-encode entry", err)
	}

	if err := ts.storage.Put(context.Background(), entry); err != nil {
		ts.FailNow("unable to store entry", err)
	}
}

func (ts *testSuite) SetupTest() {
	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)

	backendConfigEntry, err := logical.StorageEntryJSON(configRootStoragePath, ExoscaleConfig{
		APIEnvironment: testConfigAPIEnvironment,
		RootAPIKey:     testConfigRootAPIKey,
		RootAPISecret:  testConfigRootAPISecret,
		Zone:           testConfigZone,
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

	err = backend.Initialize(context.Background(), &logical.InitializationRequest{
		Storage: config.StorageView,
	})
	if err != nil {
		ts.T().Fatal(err)
	}
	backend.(*exoscaleBackend).exo.egoscaleClient = new(mockEgoscaleClient)

	ts.backend = backend
	ts.storage = config.StorageView
}

func (ts *testSuite) TearDownTest() {
	ts.backend = nil
	ts.storage = nil
}

func (ts *testSuite) randomID() string {
	id, err := uuid.GenerateUUID()
	if err != nil {
		ts.T().Fatalf("unable to generate a new UUID: %s", err)
	}
	return id
}

func TestSuite(t *testing.T) {
	suite.Run(t, new(testSuite))
}

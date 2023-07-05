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

	// putting raw data from a previous version of the plugin
	// in storage to see if it is able to work with it
	config.StorageView.Put(context.Background(), &logical.StorageEntry{
		Key:   "config/lease",
		Value: []byte(`{"ttl":46800000000000,"max_ttl":72000000000000}`),
	})
	config.StorageView.Put(context.Background(), &logical.StorageEntry{
		Key:   "config/root",
		Value: []byte(`{"api_environment":"api","root_api_key":"EXO0000","root_api_secret":"xxxxxxxx","zone":"ch-gva-2"}`),
	})
	config.StorageView.Put(context.Background(), &logical.StorageEntry{
		Key:   "role/mylegacyrole",
		Value: []byte(`{"operations":["list-instance-types","list-templates","list-zones"],"resources":["sos/bucket:test"],"tags":["read"],"lease_config":{"ttl":600000000000,"max_ttl":3000000000000},"renewable":false}`),
	})

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

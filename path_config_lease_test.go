package exoscale

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

var (
	testConfigLeaseTTL    = 1 * time.Hour
	testConfigLeaseMaxTTL = 2 * time.Hour
)

func (t *backendTestSuite) TestPathConfigLeaseWrite() {
	var actualLeaseConfig leaseConfig

	backend, storage := testBackend(t.T())

	_, err := backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      configLeaseStoragePath,
		Data: map[string]interface{}{
			"ttl":     testConfigLeaseTTL.String(),
			"max_ttl": testConfigLeaseMaxTTL.String(),
		},
	})
	if err != nil {
		t.FailNow("request failed", err)
	}

	entry, err := storage.Get(context.Background(), configLeaseStoragePath)
	if err != nil {
		t.FailNow("unable to retrieve entry from storage", err)
	}
	if err := entry.DecodeJSON(&actualLeaseConfig); err != nil {
		t.FailNow("unable to JSON-decode entry", err)
	}

	require.Equal(t.T(), leaseConfig{
		TTL:    testConfigLeaseTTL,
		MaxTTL: testConfigLeaseMaxTTL,
	}, actualLeaseConfig)
}

func (t *backendTestSuite) TestPathConfigLeaseRead() {
	backend, storage := testBackend(t.T())

	entry, err := logical.StorageEntryJSON(configLeaseStoragePath, leaseConfig{
		TTL:    testConfigLeaseTTL,
		MaxTTL: testConfigLeaseMaxTTL,
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
		Path:      configLeaseStoragePath,
	})
	if err != nil {
		t.FailNow("request failed", err)
	}

	require.Equal(t.T(), int64(testConfigLeaseTTL.Seconds()), res.Data["ttl"].(int64))
	require.Equal(t.T(), int64(testConfigLeaseMaxTTL.Seconds()), res.Data["max_ttl"].(int64))
}

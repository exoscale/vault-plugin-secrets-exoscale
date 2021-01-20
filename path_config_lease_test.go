package exoscale

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testConfigLeaseTTL    = 1 * time.Hour
	testConfigLeaseMaxTTL = 2 * time.Hour
)

func (ts *backendTestSuite) TestPathConfigLeaseWrite() {
	var actualLeaseConfig leaseConfig

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.UpdateOperation,
		Path:      configLeaseStoragePath,
		Data: map[string]interface{}{
			"ttl":     testConfigLeaseTTL.String(),
			"max_ttl": testConfigLeaseMaxTTL.String(),
		},
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	entry, err := ts.storage.Get(context.Background(), configLeaseStoragePath)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	if err := entry.DecodeJSON(&actualLeaseConfig); err != nil {
		ts.FailNow("unable to JSON-decode entry", err)
	}

	ts.Require().Equal(leaseConfig{
		TTL:    testConfigLeaseTTL,
		MaxTTL: testConfigLeaseMaxTTL,
	}, actualLeaseConfig)
}

func (ts *backendTestSuite) TestPathConfigLeaseRead() {
	ts.storeEntry(configLeaseStoragePath, leaseConfig{
		TTL:    testConfigLeaseTTL,
		MaxTTL: testConfigLeaseMaxTTL,
	})

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      configLeaseStoragePath,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(int64(testConfigLeaseTTL.Seconds()), res.Data["ttl"].(int64))
	ts.Require().Equal(int64(testConfigLeaseMaxTTL.Seconds()), res.Data["max_ttl"].(int64))
}

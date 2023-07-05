package exoscale

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	testConfigLeaseTTL    = 1 * time.Hour
	testConfigLeaseMaxTTL = 2 * time.Hour
)

func (ts *testSuite) TestPathConfigLeaseRead() {

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      configLeaseStoragePath,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(
		map[string]interface{}{
			"max_ttl": int64((20 * time.Hour).Seconds()),
			"ttl":     int64((13 * time.Hour).Seconds()),
		},
		res.Data)
}

func (ts *testSuite) TestPathConfigLeaseWrite() {
	var actualLeaseConfig leaseConfig

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.UpdateOperation,
		Path:      configLeaseStoragePath,
		Data: map[string]interface{}{
			"ttl":     time.Hour.String(),
			"max_ttl": (2 * time.Hour).String(),
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
		TTL:    1 * time.Hour,
		MaxTTL: 2 * time.Hour,
	}, actualLeaseConfig)

	// reset
	_, err = ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.UpdateOperation,
		Path:      configLeaseStoragePath,
		Data: map[string]interface{}{
			"max_ttl": (20 * time.Hour).String(),
			"ttl":     (13 * time.Hour).String(),
		},
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}
}

package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testRoleName       = "read-only"
	testRoleOperations = []string{
		"compute/listServiceOfferings",
		"compute/listTemplates",
		"compute/listZones",
	}
)

func (ts *backendTestSuite) TestPathListRoles() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Operations: testRoleOperations,
	})

	entries, err := ts.storage.List(context.Background(), roleStoragePathPrefix)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	ts.Require().Len(entries, 1)
}

func (ts *backendTestSuite) TestPathRoleWrite() {
	var actualRoleConfig backendRole

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			"name":       testRoleName,
			"operations": testRoleOperations,
			"ttl":        testConfigLeaseTTL,
			"max_ttl":    testConfigLeaseMaxTTL,
		},
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	entry, err := ts.storage.Get(context.Background(), roleStoragePathPrefix+testRoleName)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	if err := entry.DecodeJSON(&actualRoleConfig); err != nil {
		ts.FailNow("unable to JSON-decode entry", err)
	}

	ts.Require().Equal(backendRole{
		Operations: testRoleOperations,
		LeaseConfig: &leaseConfig{
			TTL:    testConfigLeaseTTL,
			MaxTTL: testConfigLeaseMaxTTL,
		},
	}, actualRoleConfig)
}

func (ts *backendTestSuite) TestPathRoleRead() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Operations: testRoleOperations,
	})

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      roleStoragePathPrefix + testRoleName,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(testRoleOperations, res.Data["operations"].([]string))
}

func (ts *backendTestSuite) TestPathRoleDelete() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Operations: testRoleOperations,
	})

	if _, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.DeleteOperation,
		Path:      roleStoragePathPrefix + testRoleName,
	}); err != nil {
		ts.FailNow("request failed", err)
	}

	entries, err := ts.storage.List(context.Background(), roleStoragePathPrefix)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	ts.Require().Empty(entries)
}

package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testRoleName       = "read-only"
	testRoleOperations = []string{
		"list-instance-types",
		"list-templates",
		"list-zones",
	}
	testRoleTags = []string{"read"}
)

func (ts *testSuite) TestPathListRoles() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Operations: testRoleOperations,
		Tags:       testRoleTags,
	})

	entries, err := ts.storage.List(context.Background(), roleStoragePathPrefix)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	ts.Require().Len(entries, 1)
}

func (ts *testSuite) TestPathRoleWrite() {
	var actualRoleConfig backendRole

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			"name":       testRoleName,
			"operations": testRoleOperations,
			"tags":       testRoleTags,
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
		Tags:       testRoleTags,
		LeaseConfig: &leaseConfig{
			TTL:    testConfigLeaseTTL,
			MaxTTL: testConfigLeaseMaxTTL,
		},
	}, actualRoleConfig)
}

func (ts *testSuite) TestPathRoleRead() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Operations: testRoleOperations,
		Tags:       testRoleTags,
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
	ts.Require().Equal(testRoleTags, res.Data["tags"].([]string))
}

func (ts *testSuite) TestPathRoleDelete() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Operations: testRoleOperations,
		Tags:       testRoleTags,
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

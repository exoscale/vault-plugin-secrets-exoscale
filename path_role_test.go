package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

var (
	testRoleName       = "read-only"
	testRoleOperations = []string{
		"compute/listZones",
		"compute/listServiceOfferings",
	}
)

func (t *backendTestSuite) TestPathListRoles() {
	_, storage := testBackend(t.T())

	entry, err := logical.StorageEntryJSON(roleStoragePathPrefix+testRoleName, roleConfig{
		Operations: testRoleOperations,
	})
	if err != nil {
		t.FailNow("unable to JSON-encode entry", err)
	}

	if err := storage.Put(context.Background(), entry); err != nil {
		t.FailNow("unable to store entry", err)
	}

	entries, err := storage.List(context.Background(), roleStoragePathPrefix)
	if err != nil {
		t.FailNow("unable to retrieve entry from storage", err)
	}
	require.Len(t.T(), entries, 1)
}

func (t *backendTestSuite) TestPathRoleWrite() {
	var actualRoleConfig roleConfig

	backend, storage := testBackend(t.T())

	_, err := backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
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
		t.FailNow("request failed", err)
	}

	entry, err := storage.Get(context.Background(), roleStoragePathPrefix+testRoleName)
	if err != nil {
		t.FailNow("unable to retrieve entry from storage", err)
	}
	if err := entry.DecodeJSON(&actualRoleConfig); err != nil {
		t.FailNow("unable to JSON-decode entry", err)
	}

	require.Equal(t.T(), roleConfig{
		Operations: testRoleOperations,
		LeaseConfig: &leaseConfig{
			TTL:    testConfigLeaseTTL,
			MaxTTL: testConfigLeaseMaxTTL,
		},
	}, actualRoleConfig)
}

func (t *backendTestSuite) TestPathRoleRead() {
	backend, storage := testBackend(t.T())

	entry, err := logical.StorageEntryJSON(roleStoragePathPrefix+testRoleName, roleConfig{
		Operations: testRoleOperations,
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
		Path:      roleStoragePathPrefix + testRoleName,
	})
	if err != nil {
		t.FailNow("request failed", err)
	}

	require.Equal(t.T(), testRoleOperations, res.Data["operations"].([]string))
}

func (t *backendTestSuite) TestPathRoleDelete() {
	backend, storage := testBackend(t.T())

	entry, err := logical.StorageEntryJSON(roleStoragePathPrefix+testRoleName, roleConfig{
		Operations: testRoleOperations,
	})
	if err != nil {
		t.FailNow("unable to JSON-encode entry", err)
	}

	if err := storage.Put(context.Background(), entry); err != nil {
		t.FailNow("unable to store entry", err)
	}

	if _, err := backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.DeleteOperation,
		Path:      roleStoragePathPrefix + testRoleName,
	}); err != nil {
		t.FailNow("request failed", err)
	}

	entries, err := storage.List(context.Background(), roleStoragePathPrefix)
	if err != nil {
		t.FailNow("unable to retrieve entry from storage", err)
	}
	require.Empty(t.T(), entries)
}

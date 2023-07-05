package exoscale

import (
	"context"
	"time"

	"github.com/exoscale/egoscale/v2/oapi"
	"github.com/hashicorp/vault/sdk/logical"
	mock "github.com/stretchr/testify/mock"
)

var (
	testRoleOperations = []string{
		"list-instance-types",
		"list-templates",
		"list-zones",
	}
	testRoleTags      = []string{"read"}
	testRoleResources = []string{"sos/bucket:test"}
)

const (
	testRoleName           = "read-only"
	testRoleResourceDomain = "sos"
	testRoleResourceName   = "test"
	testRoleResourceType   = "bucket"
)

func (ts *testSuite) TestPathListRoles() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, Role{
		Operations: testRoleOperations,
		Resources:  testRoleResources,
		Tags:       testRoleTags,
	})

	entries, err := ts.storage.List(context.Background(), roleStoragePathPrefix)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	ts.Require().Len(entries, 2)
}

func (ts *testSuite) TestPathRoleV2Write() {
	var actualRoleConfig Role

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			configVaultRoleName:  testRoleName,
			configRoleOperations: testRoleOperations,
			configRoleResources:  testRoleResources,
			configRoleTags:       testRoleTags,
			configRoleTTL:        testConfigLeaseTTL,
			configRoleMaxTTL:     testConfigLeaseMaxTTL,
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

	ts.Require().Equal(Role{
		Operations: testRoleOperations,
		Resources:  testRoleResources,
		Tags:       testRoleTags,
		TTL:        testConfigLeaseTTL,
		MaxTTL:     testConfigLeaseMaxTTL,
		Renewable:  true,
		Version:    "v2",
	}, actualRoleConfig)
}

func (ts *testSuite) TestPathRoleWriteV2NonRenewable() {
	var actualRoleConfig Role

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			configVaultRoleName:  testRoleName,
			configRoleOperations: testRoleOperations,
			configRoleResources:  testRoleResources,
			configRoleTags:       testRoleTags,
			configRoleTTL:        testConfigLeaseTTL,
			configRoleMaxTTL:     testConfigLeaseMaxTTL,
			configRoleRenewable:  false,
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

	ts.Require().Equal(Role{
		Operations: testRoleOperations,
		Resources:  testRoleResources,
		Tags:       testRoleTags,
		TTL:        testConfigLeaseTTL,
		MaxTTL:     testConfigLeaseMaxTTL,
		Renewable:  false,
		Version:    "v2",
	}, actualRoleConfig)
}

func (ts *testSuite) TestPathRoleWriteV2V3Mixed() {
	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			configVaultRoleName:  testRoleName,
			configRoleOperations: testRoleOperations,
			configRoleResources:  testRoleResources,
			configRoleTags:       testRoleTags,
			configRoleTTL:        testConfigLeaseTTL,
			configRoleMaxTTL:     testConfigLeaseMaxTTL,
			configRoleRenewable:  false,
			configIAMRole:        "tititoto",
		},
	})

	ts.NotNil(err)
	ts.ErrorContains(err, "iam-role cannot be used in conjunction with the deprecated field")
}

func (ts *testSuite) TestPathRoleV2Read() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, Role{
		Operations: testRoleOperations,
		Resources:  testRoleResources,
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

	ts.Require().Equal(testRoleOperations, res.Data[configRoleOperations].([]string))
	ts.Require().Equal(testRoleResources, res.Data[configRoleResources].([]string))
	ts.Require().Equal(testRoleTags, res.Data[configRoleTags].([]string))
}

func (ts *testSuite) TestPathRoleV2LegacyRead() {
	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      roleStoragePathPrefix + "mylegacyrole",
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(testRoleOperations, res.Data[configRoleOperations].([]string))
	ts.Require().Equal(testRoleResources, res.Data[configRoleResources].([]string))
	ts.Require().Equal(testRoleTags, res.Data[configRoleTags].([]string))
	ts.Require().Equal(map[string]interface{}{
		"max_ttl":    float64(3000),
		"operations": testRoleOperations,
		"renewable":  false,
		"resources":  testRoleResources,
		"tags":       testRoleTags,
		"ttl":        float64(600),
	}, res.Data)
}

func (ts *testSuite) TestPathRoleDelete() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, Role{
		Operations: testRoleOperations,
		Resources:  testRoleResources,
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
	ts.Require().NotContains(entries, testRoleName)
}

func (ts *testSuite) TestPathRoleV3Write() {
	iamrolename := "myiamrole"
	roleid := ts.randomID()
	name := "superv3role"

	ts.backend.(*exoscaleBackend).exo.egoscaleClient.(*mockEgoscaleClient).
		On("ListIamRolesWithResponse", mock.Anything).
		Run(func(args mock.Arguments) {
		}).
		Return(&oapi.ListIamRolesResponse{
			JSON200: &struct {
				IamRoles *[]oapi.IamRole "json:\"iam-roles,omitempty\""
			}{
				IamRoles: &[]oapi.IamRole{{
					Name: &iamrolename,
					Id:   &roleid,
				}},
			},
		}, nil)

	var actualRoleConfig Role

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + name,
		Data: map[string]interface{}{
			configVaultRoleName: name,
			configIAMRole:       iamrolename,
			configRoleTTL:       42,
			configRoleMaxTTL:    84,
		},
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	entry, err := ts.storage.Get(context.Background(), roleStoragePathPrefix+name)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	if err := entry.DecodeJSON(&actualRoleConfig); err != nil {
		ts.FailNow("unable to JSON-decode entry", err)
	}

	ts.Require().Equal(Role{
		TTL:         42 * time.Second,
		MaxTTL:      84 * time.Second,
		IAMRoleName: iamrolename,
		IAMRoleID:   roleid,
		Renewable:   true,
		Version:     "v3",
	}, actualRoleConfig)
}

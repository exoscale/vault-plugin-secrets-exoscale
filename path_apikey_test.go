package exoscale

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/exoscale/egoscale/v2/oapi"
)

var (
	testIAMAccessKeyKey     = "EXOxxxxxxxxxxxxxxxxxxxxxxxx"
	testIAMAccessKeySecret  = "yyyyyyyyy-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	testIAMAccessKeyType    = string(oapi.AccessKeyTypeRestricted)
	testIAMAccessKeyVersion = string(oapi.AccessKeyVersionV2)
)

func (ts *testSuite) TestPathV2LegacyAPIKey() {
	var (
		actualIAMAccessKeyName string
		testLeaseTTL           = 10 * time.Minute
		testLeaseMaxTTL        = 50 * time.Minute
	)

	var created bool

	ts.backend.(*exoscaleBackend).exo.egoscaleClient.(*mockEgoscaleClient).
		On("CreateIAMAccessKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			actualIAMAccessKeyName = args.Get(2).(string)

			ts.Require().Contains(actualIAMAccessKeyName, "vault-mylegacyrole-test-")
			created = true
		}).
		Return(&egoscale.IAMAccessKey{
			Key:        &testIAMAccessKeyKey,
			Name:       &actualIAMAccessKeyName,
			Operations: &testRoleOperations,
			Resources: &[]egoscale.IAMAccessKeyResource{{
				Domain:       testRoleResourceDomain,
				ResourceName: testRoleResourceName,
				ResourceType: testRoleResourceType,
			}},
			Secret:  &testIAMAccessKeySecret,
			Tags:    &testRoleTags,
			Type:    &testIAMAccessKeyType,
			Version: &testIAMAccessKeyVersion,
		}, nil)

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:     ts.storage,
		Operation:   logical.ReadOperation,
		Path:        "apikey/mylegacyrole",
		DisplayName: "test",
	})

	ts.Require().NoError(err)
	ts.Require().Equal(actualIAMAccessKeyName, res.Data[apiKeySecretDataName])
	ts.Require().Equal(testIAMAccessKeyKey, res.Data[apiKeySecretDataAPIKey])
	ts.Require().Equal(testIAMAccessKeySecret, res.Data[apiKeySecretDataAPISecret])
	ts.Require().Equal(testIAMAccessKeyKey, res.Secret.InternalData[apiKeySecretDataAPIKey])
	ts.Require().Equal(testLeaseTTL, res.Secret.TTL)
	ts.Require().Equal(testLeaseMaxTTL, res.Secret.MaxTTL)
	ts.Require().True(created)
}

func (ts *testSuite) TestPathV2APIKey() {
	var (
		actualIAMAccessKeyName string
		testLeaseTTL           = 3 * time.Second
		testLeaseMaxTTL        = 1 * time.Hour
	)

	ts.storeEntry(roleStoragePathPrefix+testRoleName, Role{
		Operations: testRoleOperations,
		Resources:  testRoleResources,
		Tags:       testRoleTags,
	})
	ts.storeEntry(configLeaseStoragePath, leaseConfig{
		TTL:    testLeaseTTL,
		MaxTTL: testLeaseMaxTTL,
	})

	ts.backend.(*exoscaleBackend).exo.egoscaleClient.(*mockEgoscaleClient).
		On("CreateIAMAccessKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ts.Require().Regexp("^vault-preproduction-projecta-"+testRoleName+"-test-[0-9]{19}-deprecated$", args.Get(2).(string))
		}).
		Return(&egoscale.IAMAccessKey{
			Key:        &testIAMAccessKeyKey,
			Name:       &actualIAMAccessKeyName,
			Operations: &testRoleOperations,
			Resources: &[]egoscale.IAMAccessKeyResource{{
				Domain:       testRoleResourceDomain,
				ResourceName: testRoleResourceName,
				ResourceType: testRoleResourceType,
			}},
			Secret:  &testIAMAccessKeySecret,
			Tags:    &testRoleTags,
			Type:    &testIAMAccessKeyType,
			Version: &testIAMAccessKeyVersion,
		}, nil)

	ts.backend.(*exoscaleBackend).exo.apiKeyNamePrefix = "preproduction-projecta"
	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:     ts.storage,
		Operation:   logical.ReadOperation,
		Path:        "apikey/" + testRoleName,
		DisplayName: "test",
	})
	ts.backend.(*exoscaleBackend).exo.apiKeyNamePrefix = ""

	ts.Require().NoError(err)
	ts.Require().Equal(actualIAMAccessKeyName, res.Data[apiKeySecretDataName])
	ts.Require().Equal(testIAMAccessKeyKey, res.Data[apiKeySecretDataAPIKey])
	ts.Require().Equal(testIAMAccessKeySecret, res.Data[apiKeySecretDataAPISecret])
	ts.Require().Equal(testIAMAccessKeyKey, res.Secret.InternalData[apiKeySecretDataAPIKey])
	ts.Require().Equal(testLeaseTTL, res.Secret.TTL)
	ts.Require().Equal(testLeaseMaxTTL, res.Secret.MaxTTL)
}

func (ts *testSuite) TestPathV3APIKey() {
	roleName := strings.TrimPrefix(ts.T().Name(), "TestSuite/")

	ts.storeEntry(roleStoragePathPrefix+roleName, Role{
		IAMRoleID:   "f7956761-068e-488b-b1b4-29790b58a697",
		IAMRoleName: "iamrole-blabla",
		Renewable:   false,
		TTL:         12 * time.Second,
		MaxTTL:      24 * time.Second,
		Version:     "v3",
	})

	var apikeyname string
	var roleid string
	ts.backend.(*exoscaleBackend).exo.egoscaleClient.(*mockEgoscaleClient).
		On("CreateApiKeyWithResponse", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			req := args.Get(1).(oapi.CreateApiKeyJSONRequestBody)
			ts.Require().Regexp("^vault-"+roleName+"-test-[0-9]{19}$", req.Name)
			apikeyname = req.Name
			roleid = req.RoleId
		}).
		Return(&oapi.CreateApiKeyResponse{
			JSON200: &oapi.IamApiKeyCreated{
				Key:    &testIAMAccessKeyKey,
				Name:   &apikeyname,
				RoleId: &roleid,
				Secret: &testIAMAccessKeySecret,
			},
		}, nil)

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:     ts.storage,
		Operation:   logical.ReadOperation,
		Path:        "apikey/" + roleName,
		DisplayName: "test",
	})
	ts.Require().NoError(err)

	ts.Require().Equal(apikeyname, res.Data[apiKeySecretDataName])
	ts.Require().Equal(testIAMAccessKeyKey, res.Data[apiKeySecretDataAPIKey])
	ts.Require().Equal(testIAMAccessKeySecret, res.Data[apiKeySecretDataAPISecret])
	ts.Require().Equal(testIAMAccessKeyKey, res.Secret.InternalData[apiKeySecretDataAPIKey])
	ts.Require().Equal(12*time.Second, res.Secret.TTL)
	ts.Require().Equal(24*time.Second, res.Secret.MaxTTL)
}

func (ts *testSuite) TestPathV3APIKeyDefaultTTL() {
	roleName := strings.TrimPrefix(ts.T().Name(), "TestSuite/")

	ts.storeEntry(roleStoragePathPrefix+roleName, Role{
		IAMRoleID:   "f7956761-068e-488b-b1b4-29790b58a697",
		IAMRoleName: "iamrole-blabla",
		Renewable:   false,
		Version:     "v3",
	})

	var apikeyname string
	var roleid string
	ts.backend.(*exoscaleBackend).exo.egoscaleClient.(*mockEgoscaleClient).
		On("CreateApiKeyWithResponse", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			req := args.Get(1).(oapi.CreateApiKeyJSONRequestBody)
			ts.Require().Regexp("^vault-preproduction-projectb-"+roleName+"-test-[0-9]{19}$", req.Name)
			apikeyname = req.Name
			roleid = req.RoleId
		}).
		Return(&oapi.CreateApiKeyResponse{
			JSON200: &oapi.IamApiKeyCreated{
				Key:    &testIAMAccessKeyKey,
				Name:   &apikeyname,
				RoleId: &roleid,
				Secret: &testIAMAccessKeySecret,
			},
		}, nil)

	ts.backend.(*exoscaleBackend).exo.apiKeyNamePrefix = "preproduction-projectb"
	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:     ts.storage,
		Operation:   logical.ReadOperation,
		Path:        "apikey/" + roleName,
		DisplayName: "test",
	})
	ts.backend.(*exoscaleBackend).exo.apiKeyNamePrefix = ""
	ts.Require().NoError(err)

	ts.Require().Equal(apikeyname, res.Data[apiKeySecretDataName])
	ts.Require().Equal(testIAMAccessKeyKey, res.Data[apiKeySecretDataAPIKey])
	ts.Require().Equal(testIAMAccessKeySecret, res.Data[apiKeySecretDataAPISecret])
	ts.Require().Equal(testIAMAccessKeyKey, res.Secret.InternalData[apiKeySecretDataAPIKey])
	ts.Require().Equal(24*time.Hour, res.Secret.TTL)
	ts.Require().Equal(time.Duration(0), res.Secret.MaxTTL)
}

func (ts *testSuite) TestPathAPIKeyUknRole() {
	roleName := strings.TrimPrefix(ts.T().Name(), "TestSuite/")

	resp, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:     ts.storage,
		Operation:   logical.ReadOperation,
		Path:        "apikey/" + roleName,
		DisplayName: "test",
	})
	ts.Require().NoError(err)
	ts.Require().Nil(resp.Secret)
	ts.Require().Equal("role \"TestPathAPIKeyUknRole\" not found", resp.Data["error"])
}

func (ts *testSuite) TestParseIAMAccessKeyResource() {
	tests := []struct {
		name    string
		input   string
		want    *egoscale.IAMAccessKeyResource
		wantErr bool
	}{
		{
			name:    "invalid format 1",
			input:   "lol/nope",
			wantErr: true,
		},
		{
			name:    "invalid format 2",
			input:   "lol:nope",
			wantErr: true,
		},
		{
			name:    "invalid format 3",
			input:   "/:",
			wantErr: true,
		},
		{
			name:  "ok",
			input: "sos/bucket:test",
			want: &egoscale.IAMAccessKeyResource{
				Domain:       "sos",
				ResourceName: "test",
				ResourceType: "bucket",
			},
		},
	}

	for _, tt := range tests {
		ts.T().Run(tt.name, func(t *testing.T) {
			got, err := V2ParseIAMResource(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIAMAccessKeyResource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseIAMAccessKeyResource() got = %v, want %v", got, tt.want)
			}
		})
	}
}

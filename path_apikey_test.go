package exoscale

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/exoscale/egoscale/v2/oapi"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
)

var (
	testIAMAccessKeyNamePrefix = fmt.Sprintf("vault-%s-", testRoleName)
	testIAMAccessKeyKey        = "EXOxxxxxxxxxxxxxxxxxxxxxxxx"
	testIAMAccessKeySecret     = "yyyyyyyyy-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	testIAMAccessKeyType       = string(oapi.AccessKeyTypeRestricted)
	testIAMAccessKeyVersion    = string(oapi.AccessKeyVersionV2)
	created                    bool
)

func (ts *testSuite) TestPathAPIKey() {
	var (
		actualIAMAccessKeyName string
		testLeaseTTL           = 3 * time.Second
		testLeaseMaxTTL        = 1 * time.Hour
	)

	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Operations: testRoleOperations,
		Resources:  testRoleResources,
		Tags:       testRoleTags,
	})
	ts.storeEntry(configLeaseStoragePath, leaseConfig{
		TTL:    testLeaseTTL,
		MaxTTL: testLeaseMaxTTL,
	})

	ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).
		On("CreateIAMAccessKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			actualIAMAccessKeyName = args.Get(2).(string)

			ts.Require().True(strings.HasPrefix(actualIAMAccessKeyName, testIAMAccessKeyNamePrefix))
			ts.Require().Len(args.Get(3).([]egoscale.CreateIAMAccessKeyOpt), 3)
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
		Path:        apiKeyPathPrefix + testRoleName,
		DisplayName: "test",
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(actualIAMAccessKeyName, res.Data[apiKeySecretDataName])
	ts.Require().Equal(testIAMAccessKeyKey, res.Data[apiKeySecretDataAPIKey])
	ts.Require().Equal(testIAMAccessKeySecret, res.Data[apiKeySecretDataAPISecret])
	ts.Require().Equal(testIAMAccessKeyKey, res.Secret.InternalData[apiKeySecretDataAPIKey])
	ts.Require().Equal(testLeaseTTL, res.Secret.TTL)
	ts.Require().Equal(testLeaseMaxTTL, res.Secret.MaxTTL)
	ts.Require().True(created)
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
			got, err := parseIAMAccessKeyResource(tt.input)
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

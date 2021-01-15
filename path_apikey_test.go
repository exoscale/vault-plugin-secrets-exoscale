package exoscale

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/jarcoal/httpmock"
)

var (
	testIAMNamePrefix = fmt.Sprintf("vault-%s-", testRoleName)
	testIAMKey        = "EXOxxxxxxxxxxxxxxxxxxxxxxxx"
	testIAMSecret     = "yyyyyyyyy-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
)

func (ts *backendTestSuite) TestPathAPIKey() {
	var (
		testIAMKeyName  string
		testLeaseTTL    = 3 * time.Second
		testLeaseMaxTTL = 1 * time.Hour
	)

	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{Operations: testRoleOperations})
	ts.storeEntry(configLeaseStoragePath, leaseConfig{
		TTL:    testLeaseTTL,
		MaxTTL: testLeaseMaxTTL,
	})

	httpmock.RegisterResponder("GET",
		"=~/v1.*command=createApiKey.*",
		func(req *http.Request) (*http.Response, error) {
			testIAMKeyName = req.URL.Query().Get("name")
			ts.Require().True(strings.HasPrefix(testIAMKeyName, testIAMNamePrefix))
			ts.Require().Equal(testRoleOperations,
				strings.Split(req.URL.Query().Get("operations"), ","))

			resp, err := httpmock.NewJsonResponse(http.StatusOK, struct {
				ApiKey egoscale.APIKey `json:"createapikeyresponse"`
			}{
				egoscale.APIKey{
					Type:       "restricted",
					Name:       testIAMKeyName,
					Key:        testIAMKey,
					Secret:     testIAMSecret,
					Operations: testRoleOperations,
				},
			})

			ts.Require().NoError(err)
			return resp, nil
		})

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:     ts.storage,
		Operation:   logical.ReadOperation,
		Path:        apiKeyPathPrefix + testRoleName,
		DisplayName: "test",
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(testIAMKeyName, res.Data["name"])
	ts.Require().Equal(testIAMKey, res.Data["api_key"])
	ts.Require().Equal(testIAMSecret, res.Data["api_secret"])
	ts.Require().Equal(testIAMKey, res.Secret.InternalData["api_key"])
	ts.Require().Equal(testLeaseTTL, res.Secret.TTL)
	ts.Require().Equal(testLeaseMaxTTL, res.Secret.MaxTTL)
}

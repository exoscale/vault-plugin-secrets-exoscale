package exoscale

import (
	"context"
	"net/http"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/jarcoal/httpmock"
)

func (ts *backendTestSuite) TestSecretAPIKeyRevoke() {
	var testIAMKeyName string

	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{Operations: testRoleOperations})

	httpmock.RegisterResponder("GET",
		"=~/v1.*command=createApiKey.*",
		func(req *http.Request) (*http.Response, error) {
			testIAMKeyName = req.URL.Query().Get("name")
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
	ts.Require().NoError(err)

	httpmock.RegisterResponder("GET",
		"=~/v1.*command=revokeApiKey.*",
		func(req *http.Request) (*http.Response, error) {
			ts.Require().Equal(testIAMKey, req.URL.Query().Get("key"))

			resp, err := httpmock.NewJsonResponse(http.StatusOK, struct {
				RevokeApiKeyResponse egoscale.RevokeAPIKeyResponse `json:"revokeapikeyresponse"`
			}{
				egoscale.RevokeAPIKeyResponse{Success: true},
			})

			ts.Require().NoError(err)
			return resp, nil
		})

	_, err = ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.RevokeOperation,
		Path:      res.Secret.LeaseID,
		Secret:    res.Secret,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}
	ts.Require().NoError(err)
}

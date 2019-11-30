// +build testacc

package exoscale

import (
	"os"
	"testing"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/logical"
)

func testAccBackend(t *testing.T) (*exoscaleBackend, logical.Storage, error) {
	t.Helper()

	backend, storage := testBackend(t)

	config := &backendConfig{APIEndpoint: defaultAPIEndpoint}

	if v, ok := os.LookupEnv("EXOSCALE_API_ENDPOINT"); ok {
		config.APIEndpoint = v
	}
	if v, ok := os.LookupEnv("EXOSCALE_API_KEY"); ok {
		config.RootAPIKey = v
	}
	if v, ok := os.LookupEnv("EXOSCALE_API_SECRET"); ok {
		config.RootAPISecret = v
	}

	if config.RootAPIKey == "" || config.RootAPISecret == "" {
		return nil, nil, errMissingAPICredentials
	}

	backend.exo = egoscale.NewClient(config.APIEndpoint, config.RootAPIKey, config.RootAPISecret)

	return backend, storage, nil
}

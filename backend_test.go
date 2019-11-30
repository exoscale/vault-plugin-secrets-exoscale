package exoscale

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/suite"
)

type backendTestSuite struct {
	suite.Suite
}

func TestAccBackendTestSuite(t *testing.T) {
	suite.Run(t, new(backendTestSuite))
}

func testBackend(t *testing.T) (*exoscaleBackend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	backend, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	return backend.(*exoscaleBackend), config.StorageView
}

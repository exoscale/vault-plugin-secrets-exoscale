package exoscale

import (
	"context"

	"github.com/stretchr/testify/mock"

	egoscale "github.com/exoscale/egoscale/v2"
)

type exoscaleClientMock struct {
	mock.Mock
}

func (m *exoscaleClientMock) CreateIAMAccessKey(
	ctx context.Context,
	zone string,
	name string,
	opts ...egoscale.CreateIAMAccessKeyOpt,
) (*egoscale.IAMAccessKey, error) {
	args := m.Called(ctx, zone, name, opts)
	return args.Get(0).(*egoscale.IAMAccessKey), args.Error(1)
}

func (m *exoscaleClientMock) RevokeIAMAccessKey(
	ctx context.Context,
	zone string,
	iamAccessKey *egoscale.IAMAccessKey,
) error {
	args := m.Called(ctx, zone, iamAccessKey)
	return args.Error(0)
}

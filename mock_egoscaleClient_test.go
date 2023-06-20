// Code generated by mockery v2.30.1. DO NOT EDIT.

package exoscale

import (
	context "context"

	oapi "github.com/exoscale/egoscale/v2/oapi"
	mock "github.com/stretchr/testify/mock"

	v2 "github.com/exoscale/egoscale/v2"
)

// mockEgoscaleClient is an autogenerated mock type for the egoscaleClient type
type mockEgoscaleClient struct {
	mock.Mock
}

type mockEgoscaleClient_Expecter struct {
	mock *mock.Mock
}

func (_m *mockEgoscaleClient) EXPECT() *mockEgoscaleClient_Expecter {
	return &mockEgoscaleClient_Expecter{mock: &_m.Mock}
}

// CreateApiKeyWithResponse provides a mock function with given fields: ctx, body, reqEditors
func (_m *mockEgoscaleClient) CreateApiKeyWithResponse(ctx context.Context, body oapi.CreateApiKeyJSONRequestBody, reqEditors ...oapi.RequestEditorFn) (*oapi.CreateApiKeyResponse, error) {
	_va := make([]interface{}, len(reqEditors))
	for _i := range reqEditors {
		_va[_i] = reqEditors[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, body)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *oapi.CreateApiKeyResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, oapi.CreateApiKeyJSONRequestBody, ...oapi.RequestEditorFn) (*oapi.CreateApiKeyResponse, error)); ok {
		return rf(ctx, body, reqEditors...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, oapi.CreateApiKeyJSONRequestBody, ...oapi.RequestEditorFn) *oapi.CreateApiKeyResponse); ok {
		r0 = rf(ctx, body, reqEditors...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oapi.CreateApiKeyResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, oapi.CreateApiKeyJSONRequestBody, ...oapi.RequestEditorFn) error); ok {
		r1 = rf(ctx, body, reqEditors...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockEgoscaleClient_CreateApiKeyWithResponse_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateApiKeyWithResponse'
type mockEgoscaleClient_CreateApiKeyWithResponse_Call struct {
	*mock.Call
}

// CreateApiKeyWithResponse is a helper method to define mock.On call
//   - ctx context.Context
//   - body oapi.CreateApiKeyJSONRequestBody
//   - reqEditors ...oapi.RequestEditorFn
func (_e *mockEgoscaleClient_Expecter) CreateApiKeyWithResponse(ctx interface{}, body interface{}, reqEditors ...interface{}) *mockEgoscaleClient_CreateApiKeyWithResponse_Call {
	return &mockEgoscaleClient_CreateApiKeyWithResponse_Call{Call: _e.mock.On("CreateApiKeyWithResponse",
		append([]interface{}{ctx, body}, reqEditors...)...)}
}

func (_c *mockEgoscaleClient_CreateApiKeyWithResponse_Call) Run(run func(ctx context.Context, body oapi.CreateApiKeyJSONRequestBody, reqEditors ...oapi.RequestEditorFn)) *mockEgoscaleClient_CreateApiKeyWithResponse_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]oapi.RequestEditorFn, len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(oapi.RequestEditorFn)
			}
		}
		run(args[0].(context.Context), args[1].(oapi.CreateApiKeyJSONRequestBody), variadicArgs...)
	})
	return _c
}

func (_c *mockEgoscaleClient_CreateApiKeyWithResponse_Call) Return(_a0 *oapi.CreateApiKeyResponse, _a1 error) *mockEgoscaleClient_CreateApiKeyWithResponse_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockEgoscaleClient_CreateApiKeyWithResponse_Call) RunAndReturn(run func(context.Context, oapi.CreateApiKeyJSONRequestBody, ...oapi.RequestEditorFn) (*oapi.CreateApiKeyResponse, error)) *mockEgoscaleClient_CreateApiKeyWithResponse_Call {
	_c.Call.Return(run)
	return _c
}

// CreateIAMAccessKey provides a mock function with given fields: _a0, _a1, _a2, _a3
func (_m *mockEgoscaleClient) CreateIAMAccessKey(_a0 context.Context, _a1 string, _a2 string, _a3 ...v2.CreateIAMAccessKeyOpt) (*v2.IAMAccessKey, error) {
	_va := make([]interface{}, len(_a3))
	for _i := range _a3 {
		_va[_i] = _a3[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _a0, _a1, _a2)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *v2.IAMAccessKey
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, ...v2.CreateIAMAccessKeyOpt) (*v2.IAMAccessKey, error)); ok {
		return rf(_a0, _a1, _a2, _a3...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, ...v2.CreateIAMAccessKeyOpt) *v2.IAMAccessKey); ok {
		r0 = rf(_a0, _a1, _a2, _a3...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*v2.IAMAccessKey)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, ...v2.CreateIAMAccessKeyOpt) error); ok {
		r1 = rf(_a0, _a1, _a2, _a3...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockEgoscaleClient_CreateIAMAccessKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateIAMAccessKey'
type mockEgoscaleClient_CreateIAMAccessKey_Call struct {
	*mock.Call
}

// CreateIAMAccessKey is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 string
//   - _a2 string
//   - _a3 ...v2.CreateIAMAccessKeyOpt
func (_e *mockEgoscaleClient_Expecter) CreateIAMAccessKey(_a0 interface{}, _a1 interface{}, _a2 interface{}, _a3 ...interface{}) *mockEgoscaleClient_CreateIAMAccessKey_Call {
	return &mockEgoscaleClient_CreateIAMAccessKey_Call{Call: _e.mock.On("CreateIAMAccessKey",
		append([]interface{}{_a0, _a1, _a2}, _a3...)...)}
}

func (_c *mockEgoscaleClient_CreateIAMAccessKey_Call) Run(run func(_a0 context.Context, _a1 string, _a2 string, _a3 ...v2.CreateIAMAccessKeyOpt)) *mockEgoscaleClient_CreateIAMAccessKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]v2.CreateIAMAccessKeyOpt, len(args)-3)
		for i, a := range args[3:] {
			if a != nil {
				variadicArgs[i] = a.(v2.CreateIAMAccessKeyOpt)
			}
		}
		run(args[0].(context.Context), args[1].(string), args[2].(string), variadicArgs...)
	})
	return _c
}

func (_c *mockEgoscaleClient_CreateIAMAccessKey_Call) Return(_a0 *v2.IAMAccessKey, _a1 error) *mockEgoscaleClient_CreateIAMAccessKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockEgoscaleClient_CreateIAMAccessKey_Call) RunAndReturn(run func(context.Context, string, string, ...v2.CreateIAMAccessKeyOpt) (*v2.IAMAccessKey, error)) *mockEgoscaleClient_CreateIAMAccessKey_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteApiKeyWithResponse provides a mock function with given fields: ctx, id, reqEditors
func (_m *mockEgoscaleClient) DeleteApiKeyWithResponse(ctx context.Context, id string, reqEditors ...oapi.RequestEditorFn) (*oapi.DeleteApiKeyResponse, error) {
	_va := make([]interface{}, len(reqEditors))
	for _i := range reqEditors {
		_va[_i] = reqEditors[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, id)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *oapi.DeleteApiKeyResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, ...oapi.RequestEditorFn) (*oapi.DeleteApiKeyResponse, error)); ok {
		return rf(ctx, id, reqEditors...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, ...oapi.RequestEditorFn) *oapi.DeleteApiKeyResponse); ok {
		r0 = rf(ctx, id, reqEditors...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oapi.DeleteApiKeyResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, ...oapi.RequestEditorFn) error); ok {
		r1 = rf(ctx, id, reqEditors...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockEgoscaleClient_DeleteApiKeyWithResponse_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteApiKeyWithResponse'
type mockEgoscaleClient_DeleteApiKeyWithResponse_Call struct {
	*mock.Call
}

// DeleteApiKeyWithResponse is a helper method to define mock.On call
//   - ctx context.Context
//   - id string
//   - reqEditors ...oapi.RequestEditorFn
func (_e *mockEgoscaleClient_Expecter) DeleteApiKeyWithResponse(ctx interface{}, id interface{}, reqEditors ...interface{}) *mockEgoscaleClient_DeleteApiKeyWithResponse_Call {
	return &mockEgoscaleClient_DeleteApiKeyWithResponse_Call{Call: _e.mock.On("DeleteApiKeyWithResponse",
		append([]interface{}{ctx, id}, reqEditors...)...)}
}

func (_c *mockEgoscaleClient_DeleteApiKeyWithResponse_Call) Run(run func(ctx context.Context, id string, reqEditors ...oapi.RequestEditorFn)) *mockEgoscaleClient_DeleteApiKeyWithResponse_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]oapi.RequestEditorFn, len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(oapi.RequestEditorFn)
			}
		}
		run(args[0].(context.Context), args[1].(string), variadicArgs...)
	})
	return _c
}

func (_c *mockEgoscaleClient_DeleteApiKeyWithResponse_Call) Return(_a0 *oapi.DeleteApiKeyResponse, _a1 error) *mockEgoscaleClient_DeleteApiKeyWithResponse_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockEgoscaleClient_DeleteApiKeyWithResponse_Call) RunAndReturn(run func(context.Context, string, ...oapi.RequestEditorFn) (*oapi.DeleteApiKeyResponse, error)) *mockEgoscaleClient_DeleteApiKeyWithResponse_Call {
	_c.Call.Return(run)
	return _c
}

// GetIamRoleWithResponse provides a mock function with given fields: ctx, id, reqEditors
func (_m *mockEgoscaleClient) GetIamRoleWithResponse(ctx context.Context, id string, reqEditors ...oapi.RequestEditorFn) (*oapi.GetIamRoleResponse, error) {
	_va := make([]interface{}, len(reqEditors))
	for _i := range reqEditors {
		_va[_i] = reqEditors[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, id)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *oapi.GetIamRoleResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, ...oapi.RequestEditorFn) (*oapi.GetIamRoleResponse, error)); ok {
		return rf(ctx, id, reqEditors...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, ...oapi.RequestEditorFn) *oapi.GetIamRoleResponse); ok {
		r0 = rf(ctx, id, reqEditors...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oapi.GetIamRoleResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, ...oapi.RequestEditorFn) error); ok {
		r1 = rf(ctx, id, reqEditors...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockEgoscaleClient_GetIamRoleWithResponse_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetIamRoleWithResponse'
type mockEgoscaleClient_GetIamRoleWithResponse_Call struct {
	*mock.Call
}

// GetIamRoleWithResponse is a helper method to define mock.On call
//   - ctx context.Context
//   - id string
//   - reqEditors ...oapi.RequestEditorFn
func (_e *mockEgoscaleClient_Expecter) GetIamRoleWithResponse(ctx interface{}, id interface{}, reqEditors ...interface{}) *mockEgoscaleClient_GetIamRoleWithResponse_Call {
	return &mockEgoscaleClient_GetIamRoleWithResponse_Call{Call: _e.mock.On("GetIamRoleWithResponse",
		append([]interface{}{ctx, id}, reqEditors...)...)}
}

func (_c *mockEgoscaleClient_GetIamRoleWithResponse_Call) Run(run func(ctx context.Context, id string, reqEditors ...oapi.RequestEditorFn)) *mockEgoscaleClient_GetIamRoleWithResponse_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]oapi.RequestEditorFn, len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(oapi.RequestEditorFn)
			}
		}
		run(args[0].(context.Context), args[1].(string), variadicArgs...)
	})
	return _c
}

func (_c *mockEgoscaleClient_GetIamRoleWithResponse_Call) Return(_a0 *oapi.GetIamRoleResponse, _a1 error) *mockEgoscaleClient_GetIamRoleWithResponse_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockEgoscaleClient_GetIamRoleWithResponse_Call) RunAndReturn(run func(context.Context, string, ...oapi.RequestEditorFn) (*oapi.GetIamRoleResponse, error)) *mockEgoscaleClient_GetIamRoleWithResponse_Call {
	_c.Call.Return(run)
	return _c
}

// ListIamRolesWithResponse provides a mock function with given fields: ctx, reqEditors
func (_m *mockEgoscaleClient) ListIamRolesWithResponse(ctx context.Context, reqEditors ...oapi.RequestEditorFn) (*oapi.ListIamRolesResponse, error) {
	_va := make([]interface{}, len(reqEditors))
	for _i := range reqEditors {
		_va[_i] = reqEditors[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *oapi.ListIamRolesResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, ...oapi.RequestEditorFn) (*oapi.ListIamRolesResponse, error)); ok {
		return rf(ctx, reqEditors...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, ...oapi.RequestEditorFn) *oapi.ListIamRolesResponse); ok {
		r0 = rf(ctx, reqEditors...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oapi.ListIamRolesResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, ...oapi.RequestEditorFn) error); ok {
		r1 = rf(ctx, reqEditors...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockEgoscaleClient_ListIamRolesWithResponse_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListIamRolesWithResponse'
type mockEgoscaleClient_ListIamRolesWithResponse_Call struct {
	*mock.Call
}

// ListIamRolesWithResponse is a helper method to define mock.On call
//   - ctx context.Context
//   - reqEditors ...oapi.RequestEditorFn
func (_e *mockEgoscaleClient_Expecter) ListIamRolesWithResponse(ctx interface{}, reqEditors ...interface{}) *mockEgoscaleClient_ListIamRolesWithResponse_Call {
	return &mockEgoscaleClient_ListIamRolesWithResponse_Call{Call: _e.mock.On("ListIamRolesWithResponse",
		append([]interface{}{ctx}, reqEditors...)...)}
}

func (_c *mockEgoscaleClient_ListIamRolesWithResponse_Call) Run(run func(ctx context.Context, reqEditors ...oapi.RequestEditorFn)) *mockEgoscaleClient_ListIamRolesWithResponse_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]oapi.RequestEditorFn, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(oapi.RequestEditorFn)
			}
		}
		run(args[0].(context.Context), variadicArgs...)
	})
	return _c
}

func (_c *mockEgoscaleClient_ListIamRolesWithResponse_Call) Return(_a0 *oapi.ListIamRolesResponse, _a1 error) *mockEgoscaleClient_ListIamRolesWithResponse_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockEgoscaleClient_ListIamRolesWithResponse_Call) RunAndReturn(run func(context.Context, ...oapi.RequestEditorFn) (*oapi.ListIamRolesResponse, error)) *mockEgoscaleClient_ListIamRolesWithResponse_Call {
	_c.Call.Return(run)
	return _c
}

// RevokeIAMAccessKey provides a mock function with given fields: _a0, _a1, _a2
func (_m *mockEgoscaleClient) RevokeIAMAccessKey(_a0 context.Context, _a1 string, _a2 *v2.IAMAccessKey) error {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *v2.IAMAccessKey) error); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockEgoscaleClient_RevokeIAMAccessKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RevokeIAMAccessKey'
type mockEgoscaleClient_RevokeIAMAccessKey_Call struct {
	*mock.Call
}

// RevokeIAMAccessKey is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 string
//   - _a2 *v2.IAMAccessKey
func (_e *mockEgoscaleClient_Expecter) RevokeIAMAccessKey(_a0 interface{}, _a1 interface{}, _a2 interface{}) *mockEgoscaleClient_RevokeIAMAccessKey_Call {
	return &mockEgoscaleClient_RevokeIAMAccessKey_Call{Call: _e.mock.On("RevokeIAMAccessKey", _a0, _a1, _a2)}
}

func (_c *mockEgoscaleClient_RevokeIAMAccessKey_Call) Run(run func(_a0 context.Context, _a1 string, _a2 *v2.IAMAccessKey)) *mockEgoscaleClient_RevokeIAMAccessKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(*v2.IAMAccessKey))
	})
	return _c
}

func (_c *mockEgoscaleClient_RevokeIAMAccessKey_Call) Return(_a0 error) *mockEgoscaleClient_RevokeIAMAccessKey_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockEgoscaleClient_RevokeIAMAccessKey_Call) RunAndReturn(run func(context.Context, string, *v2.IAMAccessKey) error) *mockEgoscaleClient_RevokeIAMAccessKey_Call {
	_c.Call.Return(run)
	return _c
}

// newMockEgoscaleClient creates a new instance of mockEgoscaleClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockEgoscaleClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockEgoscaleClient {
	mock := &mockEgoscaleClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

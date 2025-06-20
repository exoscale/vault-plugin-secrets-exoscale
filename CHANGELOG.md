# Changelog

## Unreleased

## 0.4.3

### Bug Fixes

- Fix panic when CreateApiKeyWithResponse returns an error
- IAMv3: cleanup secret if the api returns "API Key not in organization"
- Improve logging and errors

## 0.4.2

### Bug Fixes

- Fix a serialization bug preventing from setting a role as non-renewable

### Improvements

- go.mk: lint with staticcheck #22

## 0.4.1

### Bug Fixes
- Fix the version string to add the "v" prefix e.g v0.4.1 instead of 0.4.0 [#20](https://github.com/exoscale/vault-plugin-secrets-exoscale/pull/20)

## 0.4.0

⚠️  This version has [a bug related to plugin versionning](https://github.com/exoscale/vault-plugin-secrets-exoscale/pull/20)⚠️, it is recommended to skip it and install 0.4.1 directly ⚠️

### Features

- Add support for the new role based IAM

### Improvements

- automate release with Exoscale Tooling GPG key #19

## 0.3.0

* Add option to make secret non-renewable

## 0.2.3

### Bug Fixes
* Stop renewing if the TTL is capped by MaxTTL ([#13](https://github.com/exoscale/vault-plugin-secrets-exoscale/pull/13))

## 0.2.2

### Bug Fixes
* Use ttl and max_ttl from the role when renewing a lease

## 0.2.1

### Bug Fixes

* Honor api_environment backend configuration property


## 0.2.0

### Changes

* An Exoscale zone is now required during backend configuration

### Features

* Add support for resource-level IAM access key restrictions in backend role configuration


## 0.1.1

Update egoscale Go module


## 0.1.0

Initial release

# Changelog

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

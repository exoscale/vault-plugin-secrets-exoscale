# Vault Plugin: Exoscale Secrets Backend

[![Actions Status](https://github.com/exoscale/vault-plugin-secrets-exoscale/workflows/CI/badge.svg)](https://github.com/exoscale/vault-plugin-secrets-exoscale/actions?query=workflow%3ACI)

This is a [backend plugin][vaultdocplugins] plugin to be used with HashiCorp [Vault](https://www.vaultproject.io/). This plugin generates Exoscale IAM API keys which can be restricted to specific operations according to predefined roles.

This guide assumes you have already installed Vault and have a basic understanding of how Vault works. Otherwise, first read this guide on how to [get started with Vault][vaultdocintro].

**Please note**: If you believe you have found a security issue in this plugin, _please responsibly disclose_ by contacting us at [security@exoscale.com](mailto:security@exoscale.com) instead of opening an issue at GitHub.

## Quick Links

- [Vault Website](https://www.vaultproject.io)
- [Exoscale IAM Docs](https://community.exoscale.com/documentation/iam/)

## Installation

### Using pre-built releases (recommended)

You can find pre-built releases of the plugin [here][ghreleases]. Once you have downloaded the latest archive corresponding to your target OS, uncompress it to retrieve the `vault-plugin-secrets-exoscale` plugin binary file.

### From Sources

If you prefer to build the plugin from sources, clone the GitHub repository locally and run the command `make build` from the root of the sources directory. Upon successful compilation, the resulting `vault-plugin-secrets-exoscale` binary is stored in the `bin/` directory.

## Configuration

Copy the plugin binary into a location of your choice; this directory must be specified as the [`plugin_directory`][vaultdocplugindir] in the Vault configuration file:

```hcl
plugin_directory = "path/to/plugin/directory"
```

Start a Vault server with this configuration file:

```sh
$ vault server -config=path/to/vault/config.hcl
```

Once the server is started, register the plugin in the Vault server's [plugin catalog][vaultdocplugincatalog]:

```sh
$ vault write sys/plugins/catalog/secret/exoscale \
    sha_256="$(sha256sum path/to/plugin/directory/vault-plugin-secrets-exoscale | cut -d " " -f 1)" \
    command="vault-plugin-secrets-exoscale"
```

You can now enable the Exoscale secrets plugin:

```sh
$ vault secrets enable -plugin-name="exoscale" plugin
```

## Usage

### Secrets Backend Configuration

In order to be able to issue Vault secrets, the backend must be configured with root Exoscale API credentials and an Exoscale zone beforehand:

```sh
$ vault write exoscale/config/root         \
    root_api_key=${EXOSCALE_API_KEY}       \
    root_api_secret=${EXOSCALE_API_SECRET} \
    zone=ch-gva-2
```

Optionally, Exoscale API key [secrets lease][vaultdoclease] duration can be set at backend level (by default, the Vault server system-level value is used):

```sh
vault write exoscale/config/lease \
    ttl=24h \
    max_ttl=48h
```

### Backend Roles

Backend *roles* are strictly Vault-local, there is no such concept in the Exoscale IAM service: when creating a role, you can optionally specify a list of API operations that Vault-generated API keys will be restricted to when referencing this role. If no operations are specified during the role creation, resulting API keys based on this role will be unrestricted.

Note: if the Exoscale root API key configured in the backend is itself restricted, you will not be able to specify API operations that the root API key is not allowed to perform; the list of available API operations is documented on the [Exoscale API website][exoapidoc].

```sh
$ vault write exoscale/role/list-only \
	operations=list-zones,list-instance-types \
    renewable=true

```

###  Exoscale API Keys Secrets

Exoscale API key secrets are tied to a backend role, depending on which the generated API key may be restricted to certain API operations set in the specified role.

```sh
$ vault read exoscale/apikey/list-only
```

Note: the Vault backend doesn't store the generated API credentials, **there is no way to recover an API secret after it's been returned during the secret creation**.

### Documentation

The complete backend plugin usage documentation is available through the command `vault path-help exoscale`.

[vaultdocintro]: https://www.vaultproject.io/intro/getting-started/install.html
[vaultdocplugins]: https://www.vaultproject.io/docs/internals/plugins.html
[vaultdocplugindir]: https://www.vaultproject.io/docs/configuration/index.html#plugin_directory
[vaultdocplugincatalog]: https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog
[vaultdoclease]: https://www.vaultproject.io/docs/concepts/lease.html
[ghreleases]: https://github.com/exoscale/vault-plugin-secrets-exoscale/releases
[exoapidoc]: https://api.exoscale.com/

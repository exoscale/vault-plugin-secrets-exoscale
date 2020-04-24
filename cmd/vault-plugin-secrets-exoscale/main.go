package main

import (
	"log"
	"os"

	exoscale "github.com/exoscale/vault-plugin-secrets-exoscale"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatalf("error parsing command line: %s", err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: exoscale.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Fatalf("shutting down: %s", err)
	}
}

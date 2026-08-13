package main

import (
	"context"
	"fmt"
	"os"

	awsbridge "github.com/cntryl/uno/internal/aws"
	azurebridge "github.com/cntryl/uno/internal/azure"
	"github.com/cntryl/uno/internal/cli"
	"github.com/cntryl/uno/internal/core/provider"
	gcpbridge "github.com/cntryl/uno/internal/gcp"
	opbridge "github.com/cntryl/uno/internal/onepassword"
	vaultbridge "github.com/cntryl/uno/internal/vault"
)

func main() {
	code, err := execute(context.Background(), os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(code)
	}
	if code != 0 {
		os.Exit(code)
	}
}

func execute(ctx context.Context, args []string) (int, error) {
	return executeWithRegistry(ctx, args, registry())
}

func executeWithRegistry(ctx context.Context, args []string, providers *provider.Registry) (int, error) {
	return cli.ExecuteWithRegistry(ctx, args, providers)
}

func registry() *provider.Registry {
	r := provider.NewRegistry()
	opf := opbridge.Factory{}
	awsf := awsbridge.Factory{}
	r.Register("op", opf)
	r.Register("aws-secrets-manager", awsf)
	r.Register("aws-secrets-manager-arn", awsf)
	r.Register("aws-ssm", awsf)
	r.Register("azure-key-vault", azurebridge.Factory{})
	r.Register("vault", vaultbridge.Factory{})
	r.Register("gcp-secret-manager", gcpbridge.Factory{})
	return r
}

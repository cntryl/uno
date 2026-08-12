package aws

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/cntryl/uno/internal/core/provider"
)

type Factory struct{}

func (Factory) CapabilityVariables() []string {
	return []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_SDK_LOAD_CONFIG",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
		"AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
	}
}

func (Factory) Parse(raw string) (provider.Reference, error) { return Parse(raw) }

func (Factory) Adapter(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(ref.Region))
	if err != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	if ref.Scheme == "aws-ssm" {
		return &SSM{C: ssm.NewFromConfig(cfg)}, nil
	}
	return &Secrets{C: secretsmanager.NewFromConfig(cfg)}, nil
}

var completeSecretARN = regexp.MustCompile(`^(arn:[^:]+:secretsmanager:([^:]+):[0-9]{12}:secret:.+-[A-Za-z0-9]{6})(?:/([^/]+))?$`)

func Parse(raw string) (provider.Reference, error) {
	if strings.ContainsRune(raw, 0) {
		return invalidReference()
	}
	switch {
	case strings.HasPrefix(raw, "aws-secrets-manager://"):
		return parseSecretName(strings.TrimPrefix(raw, "aws-secrets-manager://"))
	case strings.HasPrefix(raw, "aws-secrets-manager-arn://"):
		return parseSecretARN(strings.TrimPrefix(raw, "aws-secrets-manager-arn://"))
	case strings.HasPrefix(raw, "aws-ssm://"):
		return parseParameter(strings.TrimPrefix(raw, "aws-ssm://"))
	default:
		return invalidReference()
	}
}

func parseSecretName(raw string) (provider.Reference, error) {
	parts := strings.Split(raw, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return invalidReference()
	}
	name, err := url.PathUnescape(parts[1])
	if err != nil || name == "" {
		return invalidReference()
	}
	key := ""
	if len(parts) == 3 {
		key = parts[2]
		if key == "" {
			return invalidReference()
		}
	}
	return provider.Reference{Scheme: "aws-secrets-manager", Region: parts[0], Container: name, Key: key, AdapterKey: "secrets-manager\x00" + parts[0]}, nil
}

func parseSecretARN(raw string) (provider.Reference, error) {
	match := completeSecretARN.FindStringSubmatch(raw)
	if match == nil {
		return invalidReference()
	}
	return provider.Reference{Scheme: "aws-secrets-manager-arn", Region: match[2], Container: match[1], Key: match[3], AdapterKey: "secrets-manager\x00" + match[2]}, nil
}

func parseParameter(raw string) (provider.Reference, error) {
	separator := strings.IndexByte(raw, '/')
	if separator <= 0 || separator == len(raw)-1 {
		return invalidReference()
	}
	return provider.Reference{Scheme: "aws-ssm", Region: raw[:separator], Container: "/" + strings.TrimLeft(raw[separator+1:], "/"), AdapterKey: "ssm\x00" + raw[:separator]}, nil
}

func invalidReference() (provider.Reference, error) {
	return provider.Reference{}, &provider.Error{Kind: provider.InvalidBinding}
}

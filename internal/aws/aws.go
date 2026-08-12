// Package aws adapts explicit AWS Secrets Manager and SSM references.
package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type Factory struct{}

func (Factory) Parse(raw string) (provider.Reference, error) { return Parse(raw) }
func (Factory) Adapter(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	return New(ctx, ref)
}

var completeSecretARN = regexp.MustCompile(`^(arn:[^:]+:secretsmanager:([^:]+):[0-9]{12}:secret:.+-[A-Za-z0-9]{6})(?:/([^/]+))?$`)

func Parse(raw string) (provider.Reference, error) {
	if strings.ContainsRune(raw, 0) {
		return invalid()
	}
	switch {
	case strings.HasPrefix(raw, "aws-secrets-manager://"):
		rest := strings.TrimPrefix(raw, "aws-secrets-manager://")
		parts := strings.Split(rest, "/")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
			return invalid()
		}
		name, err := url.PathUnescape(parts[1])
		if err != nil || name == "" {
			return invalid()
		}
		key := ""
		if len(parts) == 3 {
			key = parts[2]
			if key == "" {
				return invalid()
			}
		}
		return provider.Reference{Scheme: "aws-secrets-manager", Region: parts[0], Container: name, Key: key}, nil
	case strings.HasPrefix(raw, "aws-secrets-manager-arn://"):
		match := completeSecretARN.FindStringSubmatch(strings.TrimPrefix(raw, "aws-secrets-manager-arn://"))
		if match == nil {
			return invalid()
		}
		return provider.Reference{Scheme: "aws-secrets-manager-arn", Region: match[2], Container: match[1], Key: match[3]}, nil
	case strings.HasPrefix(raw, "aws-ssm://"):
		rest := strings.TrimPrefix(raw, "aws-ssm://")
		i := strings.IndexByte(rest, '/')
		if i <= 0 || i == len(rest)-1 {
			return invalid()
		}
		return provider.Reference{Scheme: "aws-ssm", Region: rest[:i], Container: "/" + strings.TrimLeft(rest[i+1:], "/")}, nil
	default:
		return invalid()
	}
}
func invalid() (provider.Reference, error) {
	return provider.Reference{}, &provider.Error{Kind: provider.InvalidBinding}
}

func New(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(ref.Region))
	if err != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	if ref.Scheme == "aws-ssm" {
		return &SSM{C: ssm.NewFromConfig(cfg)}, nil
	}
	return &Secrets{C: sm.NewFromConfig(cfg)}, nil
}

type SecretsAPI interface {
	GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (*sm.GetSecretValueOutput, error)
	CreateSecret(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (*sm.CreateSecretOutput, error)
	PutSecretValue(context.Context, *sm.PutSecretValueInput, ...func(*sm.Options)) (*sm.PutSecretValueOutput, error)
	UpdateSecretVersionStage(context.Context, *sm.UpdateSecretVersionStageInput, ...func(*sm.Options)) (*sm.UpdateSecretVersionStageOutput, error)
}
type Secrets struct{ C SecretsAPI }

func (s *Secrets) Read(ctx context.Context, ref provider.Reference) (secret.Value, error) {
	values, err := s.ReadMany(ctx, []provider.Reference{ref})
	if err != nil {
		return secret.Value{}, err
	}
	return values[0], nil
}
func (s *Secrets) Write(ctx context.Context, w []provider.Write) (provider.Receipt, error) {
	return s.WriteMany(ctx, w)
}

func (s *Secrets) ReadMany(ctx context.Context, refs []provider.Reference) ([]secret.Value, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	out, err := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &refs[0].Container})
	if err != nil {
		return nil, remoteError(err)
	}
	if out.SecretString == nil {
		return nil, &provider.Error{Kind: provider.InvalidState}
	}
	values := make([]secret.Value, 0, len(refs))
	fail := func(err error) ([]secret.Value, error) {
		for i := range values {
			values[i].Destroy()
		}
		return nil, err
	}
	doc := map[string]json.RawMessage{}
	parsed := false
	for _, ref := range refs {
		if ref.Container != refs[0].Container {
			return fail(&provider.Error{Kind: provider.InvalidBinding})
		}
		if ref.Blob() {
			values = append(values, secret.New(*out.SecretString))
			continue
		}
		if !parsed {
			if json.Unmarshal([]byte(*out.SecretString), &doc) != nil {
				return fail(&provider.Error{Kind: provider.InvalidState})
			}
			parsed = true
		}
		raw, ok := doc[ref.Key]
		if !ok || string(raw) == "null" {
			return fail(&provider.Error{Kind: provider.InvalidBinding})
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return fail(&provider.Error{Kind: provider.InvalidState})
		}
		values = append(values, secret.New(value))
	}
	return values, nil
}
func (s *Secrets) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}
	id := writes[0].Reference.Container
	for range 3 {
		out, getErr := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &id})
		if isMissing(getErr) {
			payload, err := payloadFor(nil, writes)
			if err != nil {
				return provider.Receipt{}, err
			}
			if _, err = s.C.CreateSecret(ctx, &sm.CreateSecretInput{Name: &id, SecretString: &payload}); err == nil {
				return provider.Receipt{Completed: environments(writes)}, nil
			}
			var exists *smtypes.ResourceExistsException
			if !errors.As(err, &exists) {
				return provider.Receipt{}, remoteError(err)
			}
			continue
		}
		if getErr != nil {
			return provider.Receipt{}, remoteError(getErr)
		}
		if out.VersionId == nil {
			return provider.Receipt{}, &provider.Error{Kind: provider.InvalidState}
		}
		payload, err := payloadFor(out.SecretString, writes)
		if err != nil {
			return provider.Receipt{}, err
		}
		token, err := randomToken()
		if err != nil {
			return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
		}
		stage := "UNO-PENDING-" + token
		put, err := s.C.PutSecretValue(ctx, &sm.PutSecretValueInput{SecretId: &id, SecretString: &payload, ClientRequestToken: &token, VersionStages: []string{stage}})
		if err != nil {
			return provider.Receipt{}, remoteError(err)
		}
		version := token
		if put.VersionId != nil {
			version = *put.VersionId
		}
		_, err = s.C.UpdateSecretVersionStage(ctx, &sm.UpdateSecretVersionStageInput{SecretId: &id, VersionStage: stringPtr("AWSCURRENT"), MoveToVersionId: &version, RemoveFromVersionId: out.VersionId})
		if err != nil {
			continue
		}
		_, _ = s.C.UpdateSecretVersionStage(ctx, &sm.UpdateSecretVersionStageInput{SecretId: &id, VersionStage: &stage, RemoveFromVersionId: &version})
		return provider.Receipt{Completed: environments(writes)}, nil
	}
	return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
}
func payloadFor(existing *string, writes []provider.Write) (string, error) {
	if writes[0].Reference.Blob() {
		return writes[0].Value.Reveal(), nil
	}
	doc := map[string]json.RawMessage{}
	if existing != nil {
		if json.Unmarshal([]byte(*existing), &doc) != nil {
			return "", &provider.Error{Kind: provider.InvalidState}
		}
	}
	for _, write := range writes {
		encoded, marshalErr := json.Marshal(write.Value.Reveal())
		if marshalErr != nil {
			return "", &provider.Error{Kind: provider.InvalidState}
		}
		doc[write.Reference.Key] = encoded
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return "", &provider.Error{Kind: provider.InvalidState}
	}
	return string(encoded), nil
}
func randomToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func stringPtr(s string) *string { return &s }

type SSMAPI interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(context.Context, *ssm.PutParameterInput, ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}
type SSM struct{ C SSMAPI }

func (s *SSM) Read(ctx context.Context, ref provider.Reference) (secret.Value, error) {
	values, err := s.ReadMany(ctx, []provider.Reference{ref})
	if err != nil {
		return secret.Value{}, err
	}
	return values[0], nil
}
func (s *SSM) Write(ctx context.Context, w []provider.Write) (provider.Receipt, error) {
	return s.WriteMany(ctx, w)
}

func (s *SSM) ReadMany(ctx context.Context, refs []provider.Reference) ([]secret.Value, error) {
	values := make([]secret.Value, 0, len(refs))
	decrypt := true
	for _, ref := range refs {
		out, err := s.C.GetParameter(ctx, &ssm.GetParameterInput{Name: &ref.Container, WithDecryption: &decrypt})
		if err != nil {
			for i := range values {
				values[i].Destroy()
			}
			return nil, remoteError(err)
		}
		if out.Parameter == nil || out.Parameter.Value == nil || out.Parameter.Type != ssmtypes.ParameterTypeSecureString {
			for i := range values {
				values[i].Destroy()
			}
			return nil, &provider.Error{Kind: provider.InvalidState}
		}
		values = append(values, secret.New(*out.Parameter.Value))
	}
	return values, nil
}
func (s *SSM) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	provider.SortedWrites(writes)
	done := []string{}
	overwrite := true
	for _, write := range writes {
		value := write.Value.Reveal()
		name := write.Reference.Container
		if _, err := s.C.PutParameter(ctx, &ssm.PutParameterInput{Name: &name, Value: &value, Type: ssmtypes.ParameterTypeSecureString, Overwrite: &overwrite}); err != nil {
			return provider.Receipt{Completed: done}, remoteError(err)
		}
		done = append(done, write.Environment)
	}
	return provider.Receipt{Completed: done}, nil
}
func environments(w []provider.Write) []string {
	out := make([]string, 0, len(w))
	for _, x := range w {
		out = append(out, x.Environment)
	}
	sort.Strings(out)
	return out
}
func isMissing(err error) bool {
	var missing *smtypes.ResourceNotFoundException
	return errors.As(err, &missing)
}
func remoteError(err error) error {
	var missingSM *smtypes.ResourceNotFoundException
	var missingSSM *ssmtypes.ParameterNotFound
	if errors.As(err, &missingSM) || errors.As(err, &missingSSM) {
		return &provider.Error{Kind: provider.InvalidBinding}
	}
	return &provider.Error{Kind: provider.Indeterminate}
}

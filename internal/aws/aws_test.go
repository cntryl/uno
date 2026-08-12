package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

func TestParsesReferences(t *testing.T) {
	cases := map[string]provider.Reference{
		"aws-secrets-manager://us-east-1/team%2Fservice/key":                                                     {Scheme: "aws-secrets-manager", Region: "us-east-1", Container: "team/service", Key: "key"},
		"aws-secrets-manager-arn://arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/service-Ab12Cd/key": {Scheme: "aws-secrets-manager-arn", Region: "us-west-2", Container: "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/service-Ab12Cd", Key: "key"},
		"aws-ssm://eu-west-1/full/parameter/path":                                                                {Scheme: "aws-ssm", Region: "eu-west-1", Container: "/full/parameter/path"},
	}
	for raw, want := range cases {
		got, err := Parse(raw)
		if err != nil || got != want {
			t.Fatalf("%s: got=%#v want=%#v err=%v", raw, got, want, err)
		}
	}
	for _, raw := range []string{"aws-secrets-manager://r/name/extra/key", "aws-secrets-manager-arn://arn:aws:secretsmanager:r:123:secret:name", "aws-ssm://r"} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

type fakeSecrets struct {
	value         *string
	puts, creates int
	last          string
}

func (f *fakeSecrets) GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
	if f.value == nil {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	version := "current"
	return &sm.GetSecretValueOutput{SecretString: f.value, VersionId: &version}, nil
}
func (f *fakeSecrets) CreateSecret(_ context.Context, in *sm.CreateSecretInput, _ ...func(*sm.Options)) (*sm.CreateSecretOutput, error) {
	f.creates++
	f.last = *in.SecretString
	f.value = in.SecretString
	return &sm.CreateSecretOutput{}, nil
}
func (f *fakeSecrets) PutSecretValue(_ context.Context, in *sm.PutSecretValueInput, _ ...func(*sm.Options)) (*sm.PutSecretValueOutput, error) {
	f.puts++
	f.last = *in.SecretString
	f.value = in.SecretString
	return &sm.PutSecretValueOutput{VersionId: in.ClientRequestToken}, nil
}
func (f *fakeSecrets) UpdateSecretVersionStage(context.Context, *sm.UpdateSecretVersionStageInput, ...func(*sm.Options)) (*sm.UpdateSecretVersionStageOutput, error) {
	return &sm.UpdateSecretVersionStageOutput{}, nil
}
func TestSecretsKeyedWritePreservesSiblingsAndCreatesMissing(t *testing.T) {
	existing := `{"keep":"yes","change":"old"}`
	fake := &fakeSecrets{value: &existing}
	adapter := &Secrets{C: fake}
	ref := provider.Reference{Container: "secret", Key: "change"}
	_, err := adapter.Write(context.Background(), []provider.Write{{Environment: "K", Reference: ref, Value: secret.New("new")}})
	if err != nil || !strings.Contains(fake.last, `"keep":"yes"`) || !strings.Contains(fake.last, `"change":"new"`) {
		t.Fatalf("payload=%s err=%v", fake.last, err)
	}
	missing := &fakeSecrets{}
	adapter = &Secrets{C: missing}
	_, err = adapter.Write(context.Background(), []provider.Write{{Environment: "K", Reference: ref, Value: secret.New("new")}})
	if err != nil || missing.creates != 1 {
		t.Fatalf("creates=%d err=%v", missing.creates, err)
	}
}
func TestSecretsBlobReadWrite(t *testing.T) {
	value := "raw"
	fake := &fakeSecrets{value: &value}
	adapter := &Secrets{C: fake}
	ref := provider.Reference{Container: "secret"}
	got, err := adapter.Read(context.Background(), ref)
	if err != nil || got.Reveal() != "raw" {
		t.Fatalf("got=%q err=%v", got.Reveal(), err)
	}
	_, err = adapter.Write(context.Background(), []provider.Write{{Environment: "K", Reference: ref, Value: secret.New("replacement")}})
	if err != nil || fake.last != "replacement" {
		t.Fatalf("last=%q err=%v", fake.last, err)
	}
}

type fakeSSM struct {
	values map[string]string
	names  []string
	fail   int
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	value, ok := f.values[*in.Name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Name: in.Name, Value: &value, Type: ssmtypes.ParameterTypeSecureString}}, nil
}
func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.names = append(f.names, *in.Name)
	if len(f.names) == f.fail {
		return nil, errors.New("remote secret leak")
	}
	return &ssm.PutParameterOutput{}, nil
}
func TestSSMExactReadAndPartialSequentialWrite(t *testing.T) {
	fake := &fakeSSM{values: map[string]string{"/source": "value"}, fail: 2}
	adapter := &SSM{C: fake}
	got, err := adapter.Read(context.Background(), provider.Reference{Container: "/source"})
	if err != nil || got.Reveal() != "value" {
		t.Fatalf("got=%q err=%v", got.Reveal(), err)
	}
	writes := []provider.Write{{Environment: "B", Reference: provider.Reference{Container: "/b"}, Value: secret.New("b")}, {Environment: "A", Reference: provider.Reference{Container: "/a"}, Value: secret.New("a")}}
	receipt, err := adapter.Write(context.Background(), writes)
	if err == nil || len(receipt.Completed) != 1 || receipt.Completed[0] != "A" || strings.Contains(err.Error(), "leak") {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

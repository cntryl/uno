package aws

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"

	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

func TestParsesReferences(t *testing.T) {
	cases := map[string]provider.Reference{
		"aws-secrets-manager://us-east-1/team%2Fservice/key":                                                     {Scheme: "aws-secrets-manager", Region: "us-east-1", Container: "team/service", Key: "key", AdapterKey: "secrets-manager\x00us-east-1"},
		"aws-secrets-manager-arn://arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/service-Ab12Cd/key": {Scheme: "aws-secrets-manager-arn", Region: "us-west-2", Container: "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/service-Ab12Cd", Key: "key", AdapterKey: "secrets-manager\x00us-west-2"},
		"aws-ssm://eu-west-1/full/parameter/path":                                                                {Scheme: "aws-ssm", Region: "eu-west-1", Container: "/full/parameter/path", AdapterKey: "ssm\x00eu-west-1"},
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

func FuzzParseReference(f *testing.F) {
	for _, seed := range []string{
		"aws-secrets-manager://us-east-1/team%2Fservice/key",
		"aws-secrets-manager-arn://arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/service-Ab12Cd/key",
		"aws-ssm://eu-west-1/full/parameter/path",
		"aws-secrets-manager://",
		"aws-ssm://region",
		"aws-ssm://region/path\x00suffix",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ref, err := Parse(raw)
		if err == nil && (ref.Scheme == "" || ref.Region == "" || ref.Container == "") {
			t.Fatalf("successful parse returned incomplete reference")
		}
	})
}

type fakeSecrets struct {
	value         *string
	puts, creates int
	last          string
}

type promotionFake struct {
	current                  string
	promoteFailures          int
	cleanupFailures          int
	observeFailure           bool
	thirdPartyConflict       bool
	puts, promotes, cleanups int
	candidate                string
}

func (f *promotionFake) GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
	if f.observeFailure && f.candidate != "" {
		return nil, errors.New("observation failed")
	}
	payload := `{"keep":"yes"}`
	version := f.current
	return &sm.GetSecretValueOutput{SecretString: &payload, VersionId: &version}, nil
}

func (f *promotionFake) CreateSecret(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (*sm.CreateSecretOutput, error) {
	return nil, errors.New("unexpected create")
}
func (f *promotionFake) PutSecretValue(_ context.Context, in *sm.PutSecretValueInput, _ ...func(*sm.Options)) (*sm.PutSecretValueOutput, error) {
	f.puts++
	f.candidate = *in.ClientRequestToken
	return &sm.PutSecretValueOutput{VersionId: &f.candidate}, nil
}
func (f *promotionFake) UpdateSecretVersionStage(_ context.Context, in *sm.UpdateSecretVersionStageInput, _ ...func(*sm.Options)) (*sm.UpdateSecretVersionStageOutput, error) {
	if *in.VersionStage == "AWSCURRENT" {
		f.promotes++
		if f.promotes <= f.promoteFailures {
			if f.thirdPartyConflict {
				f.current = "third-party-" + strconv.Itoa(f.promotes)
			} else {
				f.current = f.candidate
			}
			return nil, errors.New("lost response")
		}
		f.current = f.candidate
		return &sm.UpdateSecretVersionStageOutput{}, nil
	}
	f.cleanups++
	if f.cleanups <= f.cleanupFailures {
		return nil, errors.New("cleanup failed")
	}
	return &sm.UpdateSecretVersionStageOutput{}, nil
}

func TestPromotionAndObservationFailureStillAttemptsPendingCleanup(t *testing.T) {
	fake := &promotionFake{current: "original", promoteFailures: 1, observeFailure: true}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	_, err := (&Secrets{C: fake}).WriteMany(context.Background(), []provider.Write{write})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.Indeterminate || fake.cleanups != 1 {
		t.Fatalf("cleanups=%d err=%v", fake.cleanups, err)
	}
}

func TestPromotionFailureWhoseCandidateIsCurrentSucceedsAfterCleanup(t *testing.T) {
	fake := &promotionFake{current: "original", promoteFailures: 1}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	receipt, err := (&Secrets{C: fake}).WriteMany(context.Background(), []provider.Write{write})
	if err != nil || len(receipt.Completed) != 1 || fake.puts != 1 || fake.cleanups != 1 {
		t.Fatalf("receipt=%v puts=%d cleanups=%d err=%v", receipt, fake.puts, fake.cleanups, err)
	}
}

func TestPendingCleanupFailureHasDistinctSafeKind(t *testing.T) {
	fake := &promotionFake{current: "original", cleanupFailures: 1}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	receipt, err := (&Secrets{C: fake}).WriteMany(context.Background(), []provider.Write{write})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.PendingCleanupFailed || fake.cleanups != 1 || !reflect.DeepEqual(receipt.Completed, []string{"MY_API_KEY"}) {
		t.Fatalf("receipt=%v cleanups=%d err=%v", receipt, fake.cleanups, err)
	}
}

func TestObservedSuccessfulPromotionReportsCompletedWhenCleanupFails(t *testing.T) {
	fake := &promotionFake{current: "original", promoteFailures: 1, cleanupFailures: 1}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	receipt, err := (&Secrets{C: fake}).WriteMany(context.Background(), []provider.Write{write})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.PendingCleanupFailed || !reflect.DeepEqual(receipt.Completed, []string{"MY_API_KEY"}) {
		t.Fatalf("receipt=%v err=%v", receipt, err)
	}
}

func TestUnchangedCurrentAfterPromotionErrorConsumesRetryBudget(t *testing.T) {
	fake := &promotionFake{current: "original", promoteFailures: 1}
	fake.thirdPartyConflict = false
	fake.candidate = "prevent-auto-current"
	waits := 0
	adapter := &Secrets{C: &unchangedPromotionFake{promotionFake: fake}, jitter: func(time.Duration) time.Duration { return 0 }, wait: func(context.Context, time.Duration) error { waits++; return nil }}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	receipt, err := adapter.WriteMany(context.Background(), []provider.Write{write})
	if err != nil || !reflect.DeepEqual(receipt.Completed, []string{"MY_API_KEY"}) || waits != 1 || fake.promotes != 2 {
		t.Fatalf("receipt=%v waits=%d promotes=%d err=%v", receipt, waits, fake.promotes, err)
	}
}

type unchangedPromotionFake struct{ *promotionFake }

func (f *unchangedPromotionFake) UpdateSecretVersionStage(ctx context.Context, in *sm.UpdateSecretVersionStageInput, opts ...func(*sm.Options)) (*sm.UpdateSecretVersionStageOutput, error) {
	if *in.VersionStage == "AWSCURRENT" && f.promotes == 0 {
		f.promotes++
		return nil, errors.New("transient promotion failure")
	}
	return f.promotionFake.UpdateSecretVersionStage(ctx, in, opts...)
}

func TestAmbiguousPromotionCleanupFailureHasDistinctSafeKind(t *testing.T) {
	fake := &promotionFake{current: "original", promoteFailures: 1, observeFailure: true, cleanupFailures: 1}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	_, err := (&Secrets{C: fake}).WriteMany(context.Background(), []provider.Write{write})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.PendingCleanupFailed || fake.cleanups != 1 {
		t.Fatalf("cleanups=%d err=%v", fake.cleanups, err)
	}
}

type createRaceFake struct{ attempts int }

func (f *createRaceFake) GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
	return nil, &smtypes.ResourceNotFoundException{}
}
func (f *createRaceFake) CreateSecret(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (*sm.CreateSecretOutput, error) {
	f.attempts++
	return nil, &smtypes.ResourceExistsException{}
}
func (*createRaceFake) PutSecretValue(context.Context, *sm.PutSecretValueInput, ...func(*sm.Options)) (*sm.PutSecretValueOutput, error) {
	return nil, errors.New("unexpected put")
}
func (*createRaceFake) UpdateSecretVersionStage(context.Context, *sm.UpdateSecretVersionStageInput, ...func(*sm.Options)) (*sm.UpdateSecretVersionStageOutput, error) {
	return nil, errors.New("unexpected update")
}

func TestCreateRaceWaitsBeforeRetriesButNotAfterFinalAttempt(t *testing.T) {
	fake := &createRaceFake{}
	var delays, caps []time.Duration
	a := &Secrets{C: fake, jitter: func(ceiling time.Duration) time.Duration { caps = append(caps, ceiling); return ceiling / 2 }, wait: func(_ context.Context, delay time.Duration) error { delays = append(delays, delay); return nil }}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	_, err := a.WriteMany(context.Background(), []provider.Write{write})
	if err == nil || fake.attempts != 4 || len(delays) != 3 || len(caps) != 3 || caps[0] != 200*time.Millisecond || caps[1] != 400*time.Millisecond || caps[2] != 800*time.Millisecond {
		t.Fatalf("attempts=%d delays=%v caps=%v err=%v", fake.attempts, delays, caps, err)
	}
}

func TestCreateRaceCancellationDuringBackoffIsIndeterminate(t *testing.T) {
	fake := &createRaceFake{}
	a := &Secrets{C: fake, jitter: func(time.Duration) time.Duration { return 0 }, wait: func(context.Context, time.Duration) error { return context.Canceled }}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	_, err := a.WriteMany(context.Background(), []provider.Write{write})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.Indeterminate || fake.attempts != 1 {
		t.Fatalf("attempts=%d err=%v", fake.attempts, err)
	}
}

func TestObservedThirdPartyConflictWaitsBeforeEachRetry(t *testing.T) {
	fake := &promotionFake{current: "original", promoteFailures: 4, thirdPartyConflict: true}
	waits := 0
	a := &Secrets{C: fake, jitter: func(time.Duration) time.Duration { return 0 }, wait: func(context.Context, time.Duration) error { waits++; return nil }}
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Container: "secret", Key: "key"}, Value: secret.New("new")}
	_, err := a.WriteMany(context.Background(), []provider.Write{write})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.Indeterminate || fake.puts != 4 || fake.cleanups != 4 || waits != 3 {
		t.Fatalf("puts=%d cleanups=%d waits=%d err=%v", fake.puts, fake.cleanups, waits, err)
	}
}

type interleavingSecrets struct {
	currentVersion string
	currentPayload string
	candidates     map[string]string
	promotions     int
}

func (f *interleavingSecrets) GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
	payload, version := f.currentPayload, f.currentVersion
	return &sm.GetSecretValueOutput{SecretString: &payload, VersionId: &version}, nil
}
func (*interleavingSecrets) CreateSecret(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (*sm.CreateSecretOutput, error) {
	return nil, errors.New("unexpected create")
}
func (f *interleavingSecrets) PutSecretValue(_ context.Context, in *sm.PutSecretValueInput, _ ...func(*sm.Options)) (*sm.PutSecretValueOutput, error) {
	f.candidates[*in.ClientRequestToken] = *in.SecretString
	return &sm.PutSecretValueOutput{VersionId: in.ClientRequestToken}, nil
}
func (f *interleavingSecrets) UpdateSecretVersionStage(_ context.Context, in *sm.UpdateSecretVersionStageInput, _ ...func(*sm.Options)) (*sm.UpdateSecretVersionStageOutput, error) {
	if *in.VersionStage != "AWSCURRENT" {
		return &sm.UpdateSecretVersionStageOutput{}, nil
	}
	f.promotions++
	if f.promotions == 1 {
		f.currentVersion = "concurrent"
		f.currentPayload = `{"keep":"concurrent","target":"old"}`
		return nil, errors.New("concurrent promotion")
	}
	f.currentVersion = *in.MoveToVersionId
	f.currentPayload = f.candidates[f.currentVersion]
	return &sm.UpdateSecretVersionStageOutput{}, nil
}

func TestKeyedWriteRebasesOnConcurrentSiblingUpdate(t *testing.T) {
	fake := &interleavingSecrets{
		currentVersion: "original",
		currentPayload: `{"keep":"initial","target":"old"}`,
		candidates:     map[string]string{},
	}
	adapter := &Secrets{C: fake, jitter: func(time.Duration) time.Duration { return 0 }, wait: func(context.Context, time.Duration) error { return nil }}
	write := provider.Write{Environment: "TARGET", Reference: provider.Reference{Container: "secret", Key: "target"}, Value: secret.New("new")}

	receipt, err := adapter.WriteMany(context.Background(), []provider.Write{write})
	if err != nil || !reflect.DeepEqual(receipt.Completed, []string{"TARGET"}) {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	var final map[string]string
	if err := json.Unmarshal([]byte(fake.currentPayload), &final); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(final, map[string]string{"keep": "concurrent", "target": "new"}) || fake.promotions != 2 {
		t.Fatalf("final=%v promotions=%d", final, fake.promotions)
	}
}

func TestKeyedPayloadPreservesEveryUnwrittenSibling(t *testing.T) {
	property := func(siblings map[string]string, replacement string) bool {
		delete(siblings, "__uno_target__")
		existing, err := json.Marshal(siblings)
		if err != nil {
			return false
		}
		existingString := string(existing)
		write := provider.Write{Reference: provider.Reference{Key: "__uno_target__"}, Value: secret.New(replacement)}
		payload, err := payloadFor(&existingString, []provider.Write{write})
		if err != nil {
			return false
		}
		var got, want map[string]string
		if json.Unmarshal(existing, &want) != nil || json.Unmarshal([]byte(payload), &got) != nil {
			return false
		}
		want["__uno_target__"] = replacement
		return reflect.DeepEqual(got, want)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1_000}); err != nil {
		t.Fatal(err)
	}
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
	_, err := adapter.WriteMany(context.Background(), []provider.Write{{Environment: "K", Reference: ref, Value: secret.New("new")}})
	if err != nil || !strings.Contains(fake.last, `"keep":"yes"`) || !strings.Contains(fake.last, `"change":"new"`) {
		t.Fatalf("payload=%s err=%v", fake.last, err)
	}
	missing := &fakeSecrets{}
	adapter = &Secrets{C: missing}
	_, err = adapter.WriteMany(context.Background(), []provider.Write{{Environment: "K", Reference: ref, Value: secret.New("new")}})
	if err != nil || missing.creates != 1 {
		t.Fatalf("creates=%d err=%v", missing.creates, err)
	}
}
func TestSecretsBlobReadWrite(t *testing.T) {
	value := "raw"
	fake := &fakeSecrets{value: &value}
	adapter := &Secrets{C: fake}
	ref := provider.Reference{Container: "secret"}
	got, err := adapter.ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || got[ref.Binding()].Reveal() != "raw" {
		t.Fatalf("got=%q err=%v", got[ref.Binding()].Reveal(), err)
	}
	_, err = adapter.WriteMany(context.Background(), []provider.Write{{Environment: "K", Reference: ref, Value: secret.New("replacement")}})
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
	ref := provider.Reference{Container: "/source"}
	got, err := adapter.ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || got[ref.Binding()].Reveal() != "value" {
		t.Fatalf("got=%q err=%v", got[ref.Binding()].Reveal(), err)
	}
	writes := []provider.Write{{Environment: "B", Reference: provider.Reference{Container: "/b"}, Value: secret.New("b")}, {Environment: "A", Reference: provider.Reference{Container: "/a"}, Value: secret.New("a")}}
	receipt, err := adapter.WriteMany(context.Background(), writes)
	if err == nil || len(receipt.Completed) != 1 || receipt.Completed[0] != "A" || strings.Contains(err.Error(), "leak") {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

func TestSSMPartialReceiptsAreDeterministicPrefixes(t *testing.T) {
	writes := []provider.Write{
		{Environment: "C", Reference: provider.Reference{Container: "/c"}, Value: secret.New("c")},
		{Environment: "A", Reference: provider.Reference{Container: "/a"}, Value: secret.New("a")},
		{Environment: "B", Reference: provider.Reference{Container: "/b"}, Value: secret.New("b")},
	}
	for failure := 1; failure <= len(writes); failure++ {
		fake := &fakeSSM{fail: failure}
		receipt, err := (&SSM{C: fake}).WriteMany(context.Background(), append([]provider.Write(nil), writes...))
		wantCompleted := []string{"A", "B", "C"}[:failure-1]
		wantNames := []string{"/a", "/b", "/c"}[:failure]
		if err == nil || !reflect.DeepEqual(receipt.Completed, wantCompleted) || !reflect.DeepEqual(fake.names, wantNames) {
			t.Fatalf("failure=%d completed=%v names=%v err=%v", failure, receipt.Completed, fake.names, err)
		}
	}
}

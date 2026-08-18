package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

// run executes one CLI invocation against an in-memory stdout buffer and a
// non-interactive-by-default stdin (any Runtime.Stdin that isn't an *os.File
// makes DefaultRuntime's IsTerminal report false, so tests get the
// non-interactive path for free without needing a real TTY or pipe trick).
func run(args []string, providers *provider.Registry) (int, string, error) {
	var out bytes.Buffer
	runtime := Runtime{Stdout: &out, Stdin: strings.NewReader("")}
	code, err := Execute(context.Background(), args, providers, runtime)
	return code, out.String(), err
}

func TestShouldStripProviderCredentialsGivenMixedCaseEnvironment(t *testing.T) {
	prefixes := []string{"AWS_", "OP_", "AZURE_"}
	got := SafeChildEnvironment([]string{"PATH=/bin", "AWS_REGION=us-east-1", "Aws_Access_Key_Id=mixed-secret", "op_service_account_token=mixed-token", "AWS_PROFILE=admin", "AWS_SECRET_ACCESS_KEY=secret", "AWS_FOO_BAR=x", "OP_SERVICE_ACCOUNT_TOKEN=token", "AZURE_CLIENT_SECRET=secret", "Azure_Tenant_Id=mixed-secret", "ORDINARY=value"}, prefixes)
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "ORDINARY=value") || strings.Contains(strings.ToUpper(joined), "AWS_") || strings.Contains(strings.ToUpper(joined), "OP_") || strings.Contains(strings.ToUpper(joined), "AZURE_") || strings.Contains(joined, "secret") || strings.Contains(joined, "token") {
		t.Fatalf("unsafe child environment: %v", got)
	}
}

func TestShouldStripInheritedResolvedKeysFromChildEnvironment(t *testing.T) {
	got := SafeChildEnvironment([]string{"PATH=/bin", "MY_API_KEY=stale", "my_api_key=duplicate", "OTHER=kept"}, nil, []string{"MY_API_KEY"})
	if strings.Join(got, "|") != "PATH=/bin|OTHER=kept" {
		t.Fatalf("environment=%v", got)
	}
}

type cliFactory struct{ adapter *cliAdapter }

func (f cliFactory) Parse(string) (provider.Reference, error) {
	return provider.Reference{Scheme: "fake", Container: "container", Key: "key"}, nil
}
func (f cliFactory) Adapter(context.Context, provider.Reference) (provider.Adapter, error) {
	f.adapter.accesses++
	return f.adapter, nil
}

type aliasCliFactory struct{ adapter *cliAdapter }

func (f aliasCliFactory) Parse(raw string) (provider.Reference, error) {
	parts := strings.SplitN(strings.TrimPrefix(raw, "fake://"), "/", 2)
	ref := provider.Reference{Scheme: "fake", Container: parts[0]}
	if len(parts) == 2 {
		ref.Key = parts[1]
	}
	return ref, nil
}
func (f aliasCliFactory) Adapter(context.Context, provider.Reference) (provider.Adapter, error) {
	f.adapter.accesses++
	return f.adapter, nil
}

type cliAdapter struct {
	accesses, reads, writes, readCalls int
	readBatchSizes                     []int
	value                              string
	read                               func(context.Context, []provider.Reference) (map[string]secret.Value, error)
	readResults                        func([]provider.Reference) (map[string]provider.ReadResult, error)
	write                              func(context.Context, []provider.Write) (provider.Receipt, error)
}

// ReadMany's default (no read hook) behavior models a fresh destination:
// this test harness reuses one adapter for both the source and destination
// side of a mapping (cliFactory.Parse ignores its input), so the engine's
// source-resolve call and its destination-diff call land on the exact same
// method. The first call succeeds, standing in for "read the source"; every
// call after that reports the binding as not-yet-existing, standing in for
// "this destination hasn't been written before" — which is the common case
// for a first sync, and keeps every pre-existing test's "the write step
// gets attempted" assumption true without each needing to seed a fake store.
func (a *cliAdapter) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]provider.ReadResult, error) {
	a.readBatchSizes = append(a.readBatchSizes, len(refs))
	if a.readResults != nil {
		return a.readResults(refs)
	}
	if a.read != nil {
		old, err := a.read(ctx, refs)
		out := make(map[string]provider.ReadResult, len(old))
		for key, value := range old {
			out[key] = provider.ReadResult{Value: value, Found: true}
		}
		return out, err
	}
	a.readCalls++
	if a.readCalls > 1 {
		return provider.MissingResults(refs), nil
	}
	out := make(map[string]provider.ReadResult, len(refs))
	for _, r := range refs {
		a.reads++
		value := a.value
		if value == "" {
			value = "resolved"
		}
		out[r.Binding()] = provider.ReadResult{Value: secret.New(value), Found: true}
	}
	return out, nil
}

func TestShouldLeaveSecretsFileAbsentOrUnchangedGivenMissingDevSource(t *testing.T) {
	t.Run("absent", func(t *testing.T) { testMissingDevSource(t, "") })
	t.Run("existing", func(t *testing.T) { testMissingDevSource(t, "MY_API_KEY=existing-value\n") })
}

func testMissingDevSource(t *testing.T, existing string) {
	t.Helper()
	directory := t.TempDir()
	initDevRepo(t, directory)
	if existing != "" {
		if err := os.WriteFile(".env.secrets", []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, "template")
	if err := os.WriteFile(path, []byte("# local development\n\nMY_API_KEY=fake://CANARY_REFERENCE -> fake://destination\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter := &cliAdapter{readResults: func(refs []provider.Reference) (map[string]provider.ReadResult, error) {
		return map[string]provider.ReadResult{refs[0].Binding(): {Diagnostic: provider.SecretNotFound}}, nil
	}}

	_, _, err := run([]string{"--template", path, "dev"}, cliRegistry(adapter))

	const want = "line 3: read failed: source secret not found in provider (InvalidBinding)"
	if err == nil || err.Error() != want || strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "MY_API_KEY") {
		t.Fatalf("err=%v want=%q", err, want)
	}
	assertSecretsFile(t, existing)
	if adapter.writes != 0 {
		t.Fatalf("writes=%d", adapter.writes)
	}
}

func assertSecretsFile(t *testing.T, existing string) {
	t.Helper()
	contents, err := os.ReadFile(".env.secrets")
	if existing == "" && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read err=%v contents=%q", err, contents)
	}
	if existing != "" && (err != nil || string(contents) != existing) {
		t.Fatalf("read err=%v contents=%q", err, contents)
	}
}

func TestShouldReturnInvalidArgumentsErrorGivenNonPositiveTimeout(t *testing.T) {
	path := templateFile(t)
	for _, duration := range []string{"0s", "-1s", "invalid"} {
		_, _, err := run([]string{"--template", path, "--timeout", duration, "check"}, cliRegistry(&cliAdapter{}))
		if err == nil || !strings.Contains(err.Error(), "invalid arguments") {
			t.Fatalf("duration=%q err=%v", duration, err)
		}
	}
}

func TestShouldValidateArgumentsBeforeReadingTemplate(t *testing.T) {
	code, _, err := run([]string{"--template", "missing", "unknown"}, cliRegistry(&cliAdapter{}))
	if err == nil || code != 2 || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestShouldReturnRedactedTimeoutErrorGivenBlockingProvider(t *testing.T) {
	adapter := &cliAdapter{read: func(ctx context.Context, _ []provider.Reference) (map[string]secret.Value, error) {
		<-ctx.Done()
		return nil, errors.New("remote provider leaked text")
	}}
	path := templateFile(t)
	_, _, err := run([]string{"--template", path, "--timeout", "1ms", "sync"}, cliRegistry(adapter))
	if err == nil || err.Error() != "operation timed out" {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldCompleteChildProcessGivenProviderTimeoutExpiresDuringRun(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	command := []string{"/bin/sh", "-c", "sleep 0.03; test \"$VALUE\" = resolved"}
	if runtime.GOOS == "windows" {
		command = []string{"powershell", "-NoProfile", "-Command", "Start-Sleep -Milliseconds 30; if ($env:VALUE -ne 'resolved') { exit 1 }"}
	}
	args := append([]string{"--template", path, "--timeout", "1ms", "run", "--"}, command...)
	code, _, err := run(args, cliRegistry(adapter))
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestShouldPropagateTimeoutToProviderContextGivenCustomTimeoutFlag(t *testing.T) {
	adapter := &cliAdapter{read: func(ctx context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second || time.Until(deadline) < time.Second {
			return nil, errors.New("unexpected deadline")
		}
		out := map[string]secret.Value{}
		for _, ref := range refs {
			out[ref.Binding()] = secret.New("resolved")
		}
		return out, nil
	}}
	path := templateFile(t)
	if _, _, err := run([]string{"--template", path, "--timeout", "2s", "sync"}, cliRegistry(adapter)); err != nil {
		t.Fatal(err)
	}
}

func TestShouldPropagateDefaultTimeoutToProviderContextGivenNoTimeoutFlag(t *testing.T) {
	adapter := &cliAdapter{read: func(ctx context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining > 61*time.Second || remaining < 59*time.Second {
			return nil, errors.New("unexpected deadline")
		}
		out := map[string]secret.Value{}
		for _, ref := range refs {
			out[ref.Binding()] = secret.New("resolved")
		}
		return out, nil
	}}
	path := templateFile(t)
	if _, _, err := run([]string{"--template", path, "sync"}, cliRegistry(adapter)); err != nil {
		t.Fatal(err)
	}
}

func TestShouldReportCompletedWriteGivenTimeoutDuringSync(t *testing.T) {
	adapter := &cliAdapter{write: func(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
		<-ctx.Done()
		return provider.Receipt{Completed: []string{writes[0].Environment}}, errors.New("remote provider leaked text")
	}}
	path := templateFile(t)
	_, output, gotErr := run([]string{"--template", path, "--timeout", "1ms", "sync", "--force"}, cliRegistry(adapter))
	if gotErr == nil || gotErr.Error() != "operation timed out" || output != "VALUE: create\n" {
		t.Fatalf("output=%q err=%v", output, gotErr)
	}
}

func TestShouldRefuseToWriteGivenPendingChangeWithoutForceNonInteractively(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	_, _, err := run([]string{"--template", path, "sync"}, cliRegistry(adapter))
	if err == nil || !strings.Contains(err.Error(), "--force") || adapter.writes != 0 {
		t.Fatalf("writes=%d err=%v", adapter.writes, err)
	}
}

func TestShouldWritePendingChangeGivenForceFlag(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	_, output, err := run([]string{"--template", path, "sync", "--force"}, cliRegistry(adapter))
	if err != nil {
		t.Fatal(err)
	}
	if adapter.writes != 1 || output != "VALUE: create\n" {
		t.Fatalf("writes=%d output=%q", adapter.writes, output)
	}
}

func TestShouldSkipWriteAndReportUnchangedGivenDestinationAlreadyMatches(t *testing.T) {
	adapter := &cliAdapter{read: func(_ context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
		out := make(map[string]secret.Value, len(refs))
		for _, r := range refs {
			out[r.Binding()] = secret.New("resolved")
		}
		return out, nil
	}}
	path := templateFile(t)
	_, output, err := run([]string{"--template", path, "sync"}, cliRegistry(adapter))
	if err != nil {
		t.Fatal(err)
	}
	if adapter.writes != 0 || output != "VALUE: unchanged\n" {
		t.Fatalf("writes=%d output=%q", adapter.writes, output)
	}
}

func TestShouldPrintJSONResultGivenJSONFlag(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	_, output, err := run([]string{"--template", path, "sync", "--force", "--json"}, cliRegistry(adapter))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		DryRun  bool `json:"dryRun"`
		Changes []struct {
			Environment string `json:"environment"`
			Kind        string `json:"kind"`
		} `json:"changes"`
		Completed []string `json:"completed"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output=%q err=%v", output, err)
	}
	if result.DryRun || len(result.Changes) != 1 || result.Changes[0].Environment != "VALUE" || result.Changes[0].Kind != "create" || strings.Join(result.Completed, ",") != "VALUE" {
		t.Fatalf("result=%+v output=%q", result, output)
	}
}

func (a *cliAdapter) WriteMany(ctx context.Context, w []provider.Write) (provider.Receipt, error) {
	a.writes++
	if a.write != nil {
		return a.write(ctx, w)
	}
	return provider.Receipt{Completed: []string{w[0].Environment}}, nil
}

// rollbackCliAdapter adds provider.Rollbacker to cliAdapter, so rollback
// tests can distinguish "the provider supports rollback" from the plain
// cliAdapter's baseline "provider doesn't implement it" case.
type rollbackCliAdapter struct {
	cliAdapter

	rolledBack int
	failWith   error
}

func (a *rollbackCliAdapter) Rollback(context.Context, provider.Reference) error {
	a.rolledBack++
	return a.failWith
}

// rollbackCliFactory, unlike cliFactory, holds a provider.Adapter interface
// value rather than a concrete *cliAdapter, so the adapter it returns keeps
// its real dynamic type — necessary for a provider.Rollbacker type
// assertion to see rollbackCliAdapter's promoted Rollback method. Returning
// the embedded *cliAdapter through cliFactory instead would erase it.
type rollbackCliFactory struct{ adapter provider.Adapter }

func (f rollbackCliFactory) Parse(string) (provider.Reference, error) {
	return provider.Reference{Scheme: "fake", Container: "container", Key: "key"}, nil
}
func (f rollbackCliFactory) Adapter(context.Context, provider.Reference) (provider.Adapter, error) {
	return f.adapter, nil
}
func rollbackCliRegistry(adapter provider.Adapter) *provider.Registry {
	r := provider.NewRegistry()
	r.Register("fake", rollbackCliFactory{adapter})
	return r
}

func TestShouldRollbackGivenForceFlag(t *testing.T) {
	adapter := &rollbackCliAdapter{}
	path := templateFile(t)
	_, output, err := run([]string{"--template", path, "rollback", "--force"}, rollbackCliRegistry(adapter))
	if err != nil {
		t.Fatal(err)
	}
	if adapter.rolledBack != 1 || output != "VALUE: reverted\n" {
		t.Fatalf("rolledBack=%d output=%q", adapter.rolledBack, output)
	}
}

func TestShouldRefuseRollbackWithoutForceNonInteractively(t *testing.T) {
	adapter := &rollbackCliAdapter{}
	path := templateFile(t)
	_, _, err := run([]string{"--template", path, "rollback"}, rollbackCliRegistry(adapter))
	if err == nil || !strings.Contains(err.Error(), "--force") || adapter.rolledBack != 0 {
		t.Fatalf("rolledBack=%d err=%v", adapter.rolledBack, err)
	}
}

func TestShouldReportUnsupportedGivenProviderLacksRollback(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	code, output, err := run([]string{"--template", path, "rollback", "--force"}, cliRegistry(adapter))
	if err == nil || code != 1 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if output != "VALUE: unsupported\n" {
		t.Fatalf("output=%q", output)
	}
}

func TestShouldPrintRollbackJSONResultGivenJSONFlag(t *testing.T) {
	adapter := &rollbackCliAdapter{}
	path := templateFile(t)
	_, output, err := run([]string{"--template", path, "rollback", "--force", "--json"}, rollbackCliRegistry(adapter))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Results []struct {
			Environment string `json:"environment"`
			Status      string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output=%q err=%v", output, err)
	}
	if len(result.Results) != 1 || result.Results[0].Environment != "VALUE" || result.Results[0].Status != "reverted" {
		t.Fatalf("result=%+v output=%q", result, output)
	}
}

func cliRegistry(adapter *cliAdapter) *provider.Registry {
	r := provider.NewRegistry()
	r.Register("fake", cliFactory{adapter})
	return r
}

func templateFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "template")
	if err := os.WriteFile(path, []byte("VALUE=fake://source -> fake://target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestShouldAcceptTemplateWithNoMappingsGivenCheckCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.secrets-template")
	if err := os.WriteFile(path, []byte("# mappings may be added later\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, output, err := run([]string{"--template", path, "check"}, cliRegistry(&cliAdapter{}))
	if err != nil || output != "template valid: 0 mappings\n" {
		t.Fatalf("output=%q err=%v", output, err)
	}
}

func TestShouldSkipProviderAccessGivenCheckOrDryRunCommand(t *testing.T) {
	adapter := &cliAdapter{}
	providers := cliRegistry(adapter)
	path := templateFile(t)
	if _, _, err := run([]string{"--template", path, "check"}, providers); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run([]string{"--template", path, "sync", "--dry-run"}, providers); err != nil {
		t.Fatal(err)
	}
	if adapter.accesses != 1 {
		t.Fatalf("provider accesses=%d", adapter.accesses)
	}
}

func TestShouldBindAliasMappingsToOneKeyedContainerAndKeepCheckOffline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "template")
	input := "@runtime=fake://runtime\nFIRST=fake://source/FIRST -> @runtime\nSECOND=fake://source/SECOND -> @runtime\n"
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter := &cliAdapter{}
	registry := provider.NewRegistry()
	registry.Register("fake", aliasCliFactory{adapter})
	if _, _, err := run([]string{"--template", path, "check"}, registry); err != nil {
		t.Fatal(err)
	}
	if adapter.accesses != 0 || len(adapter.readBatchSizes) != 0 {
		t.Fatalf("check contacted provider: accesses=%d batches=%v", adapter.accesses, adapter.readBatchSizes)
	}
	if _, _, err := run([]string{"--template", path, "sync", "--dry-run"}, registry); err != nil {
		t.Fatal(err)
	}
	if adapter.accesses != 1 || len(adapter.readBatchSizes) != 2 || adapter.readBatchSizes[0] != 2 || adapter.readBatchSizes[1] != 2 {
		t.Fatalf("accesses=%d read batches=%v", adapter.accesses, adapter.readBatchSizes)
	}
}

func TestShouldReadOnceAndPreserveExitCodeGivenRunCommand(t *testing.T) {
	adapter := &cliAdapter{}
	providers := cliRegistry(adapter)
	path := templateFile(t)
	command := []string{"/bin/sh", "-c", "test \"$VALUE\" = resolved; exit 7"}
	if runtime.GOOS == "windows" {
		command = []string{"powershell", "-NoProfile", "-Command", "if ($env:VALUE -ne 'resolved') { exit 1 }; exit 7"}
	}
	args := append([]string{"--template", path, "run", "--"}, command...)
	code, _, err := run(args, providers)
	if err != nil || code != 7 || adapter.reads != 1 || adapter.writes != 0 {
		t.Fatalf("code=%d reads=%d writes=%d err=%v", code, adapter.reads, adapter.writes, err)
	}
}

func TestShouldReturnMissingSeparatorErrorGivenRunWithoutDoubleDash(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	for _, args := range [][]string{
		{"--template", path, "run", "/bin/echo", "--timeout", "30s"},
		{"--template", path, "run", "/bin/echo", "--version"},
	} {
		_, _, err := run(args, cliRegistry(adapter))
		if err == nil || err.Error() != "run requires a command after --" {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
	if adapter.accesses != 0 {
		t.Fatalf("provider accesses=%d", adapter.accesses)
	}
}

func TestShouldTreatFlagValueAsNotACommandGivenGlobalFlagPrecedesSubcommand(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	if _, _, err := run([]string{"--template", path, "check"}, cliRegistry(adapter)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run([]string{"--template", "sync", "check"}, cliRegistry(adapter)); err == nil || err.Error() != "could not read secrets template" {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldPrintUsageGivenSubcommandHelpFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"sync", "--help"}, "--dry-run"},
		{[]string{"run", "--help"}, "run -- <command>"},
	} {
		_, output, err := run(tc.args, cliRegistry(&cliAdapter{}))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output, tc.want) {
			t.Fatalf("args=%v output=%q", tc.args, output)
		}
	}
}

func TestShouldPrintGlobalHelpOrVersionGivenRunWithoutSeparator(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "--version"}, "uno " + version + "\n"},
		{[]string{"--version", "run"}, "uno " + version + "\n"},
		{[]string{"--help", "run"}, "run -- <command>"},
	} {
		_, output, err := run(tc.args, cliRegistry(&cliAdapter{}))
		if err != nil {
			t.Fatalf("args=%v err=%v", tc.args, err)
		}
		if !strings.Contains(output, tc.want) {
			t.Fatalf("args=%v output=%q want substring=%q", tc.args, output, tc.want)
		}
	}
}

func TestShouldReportUnknownFlagErrorBeforeCommandDiscoveryGivenInvalidGlobalFlag(t *testing.T) {
	_, _, err := run([]string{"--foo", "bar", "check"}, cliRegistry(&cliAdapter{}))
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined: -foo") {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldTreatDoubleDashAsFlagValueGivenTemplateFlagPrecedesSeparator(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("--", []byte("VALUE=fake://source -> fake://target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter := &cliAdapter{}
	command := []string{"/usr/bin/true"}
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/C", "exit", "0"}
	}
	args := append([]string{"run", "--template", "--", "--"}, command...)
	code, _, err := run(args, cliRegistry(adapter))
	if err != nil || code != 0 || adapter.reads != 1 {
		t.Fatalf("code=%d reads=%d err=%v", code, adapter.reads, err)
	}
	if _, _, err := run([]string{"run", "--template", "--", "/usr/bin/true"}, cliRegistry(&cliAdapter{})); err == nil || err.Error() != "run requires a command after --" {
		t.Fatalf("missing separator err=%v", err)
	}
}

func TestShouldAcceptCommandGivenLeadingDoubleDashSeparator(t *testing.T) {
	path := templateFile(t)
	t.Setenv("UNO_TEMPLATE", path)
	if _, _, err := run([]string{"--", "check"}, cliRegistry(&cliAdapter{})); err != nil {
		t.Fatal(err)
	}
}

func TestShouldReturnUnknownCommandErrorGivenEmptyStringArgument(t *testing.T) {
	path := templateFile(t)
	_, _, err := run([]string{"--template", path, "", "sync", "--dry-run"}, cliRegistry(&cliAdapter{}))
	if err == nil || err.Error() != `unknown command ""` {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldPrintGlobalHelpOrVersionGivenSingleDashLongFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-version"}, "uno " + version + "\n"},
		{[]string{"-help"}, "Usage: uno"},
	} {
		_, output, err := run(tc.args, cliRegistry(&cliAdapter{}))
		if err != nil {
			t.Fatalf("args=%v err=%v", tc.args, err)
		}
		if !strings.Contains(output, tc.want) {
			t.Fatalf("args=%v output=%q", tc.args, output)
		}
	}
}

func TestShouldFormatFlagErrorAsInvalidArgumentsGivenMalformedGlobalFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--foo=bar", "check"}, "invalid arguments: flag provided but not defined: -foo"},
		{[]string{"--template"}, "invalid arguments: flag needs an argument: -template"},
	} {
		_, _, err := run(tc.args, cliRegistry(&cliAdapter{}))
		if err == nil || err.Error() != tc.want {
			t.Fatalf("args=%v err=%v want=%q", tc.args, err, tc.want)
		}
	}
}

func TestShouldWriteEscapedSecretsFileWithRestrictedPermissionsGivenDevCommand(t *testing.T) {
	adapter := &cliAdapter{value: "line one\n\"$VALUE\"\\end"}
	providers := cliRegistry(adapter)
	temporary := t.TempDir()
	initDevRepo(t, temporary)
	path := templateFile(t)
	if _, _, err := run([]string{"--template", path, "dev"}, providers); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(".env.secrets")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "VALUE=\"line one\\n\\\"$VALUE\\\"\\\\end\"\n"; got != want {
		t.Fatalf("contents=%q want=%q", got, want)
	}
	info, err := os.Stat(".env.secrets")
	if err != nil {
		t.Fatal(err)
	}
	if (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) || adapter.reads != 1 || adapter.writes != 0 {
		t.Fatalf("mode=%o reads=%d writes=%d", info.Mode().Perm(), adapter.reads, adapter.writes)
	}
}

func TestShouldLeaveExistingSecretsFileUnchangedGivenDevTemplateWithNoMappings(t *testing.T) {
	adapter := &cliAdapter{}
	initDevRepo(t, t.TempDir())
	const existing = "MY_API_KEY=existing-value\n"
	if err := os.WriteFile(".env.secrets", []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), ".env.secrets-template")
	if err := os.WriteFile(path, []byte("# mappings may be added later\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, output, err := run([]string{"--template", path, "dev"}, cliRegistry(adapter))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(".env.secrets")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existing || adapter.accesses != 0 || adapter.reads != 0 {
		t.Fatalf("contents=%q accesses=%d reads=%d", data, adapter.accesses, adapter.reads)
	}
	if output != "no mappings; left .env.secrets unchanged\n" {
		t.Fatalf("output=%q", output)
	}
}

func TestShouldIgnoreUnsetDestinationAliasEnvironmentGivenDevCommand(t *testing.T) {
	adapter := &cliAdapter{}
	providers := provider.NewRegistry()
	providers.Register("fake", aliasCliFactory{adapter})
	temporary := t.TempDir()
	initDevRepo(t, temporary)
	path := filepath.Join(temporary, "template")
	input := "@runtime=fake://$DESTINATION_CONTAINER\nVALUE=fake://source/VALUE -> @runtime\n"
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	runtime := Runtime{
		Stdout:    &out,
		Stdin:     strings.NewReader(""),
		LookupEnv: func(string) (string, bool) { return "", false },
	}
	if _, err := Execute(t.Context(), []string{"--template", path, "check"}, providers, runtime); err == nil || !strings.Contains(err.Error(), "environment variable DESTINATION_CONTAINER is not set") {
		t.Fatalf("check err=%v", err)
	}
	if _, err := Execute(t.Context(), []string{"--template", path, "dev"}, providers, runtime); err != nil {
		t.Fatal(err)
	}
	if adapter.reads != 1 || adapter.writes != 0 {
		t.Fatalf("reads=%d writes=%d", adapter.reads, adapter.writes)
	}
	data, err := os.ReadFile(".env.secrets")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "VALUE=\"resolved\"\n"; got != want {
		t.Fatalf("contents=%q want=%q", got, want)
	}
}
func initDevRepo(t *testing.T, directory string) {
	t.Helper()
	t.Chdir(directory)
	if err := exec.CommandContext(t.Context(), "git", "init", "-q").Run(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".gitignore", []byte(".env.secrets*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestShouldFailBeforeProviderAccessGivenMissingGitignoreOnDevCommand(t *testing.T) {
	adapter := &cliAdapter{}
	providers := cliRegistry(adapter)
	t.Chdir(t.TempDir())
	path := templateFile(t)
	if _, _, err := run([]string{"--template", path, "dev"}, providers); err == nil {
		t.Fatal("expected missing .gitignore failure")
	}
	if adapter.accesses != 0 || adapter.reads != 0 {
		t.Fatalf("accesses=%d reads=%d", adapter.accesses, adapter.reads)
	}
}

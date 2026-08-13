package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

func TestShouldStripProviderCredentialsGivenMixedCaseEnvironment(t *testing.T) {
	got := safeChildEnvironment([]string{"PATH=/bin", "AWS_REGION=us-east-1", "Aws_Access_Key_Id=mixed-secret", "op_service_account_token=mixed-token", "AWS_PROFILE=admin", "AWS_SECRET_ACCESS_KEY=secret", "AWS_FOO_BAR=x", "OP_SERVICE_ACCOUNT_TOKEN=token", "AZURE_CLIENT_SECRET=secret", "Azure_Tenant_Id=mixed-secret", "ORDINARY=value"}, registry().CapabilityPrefixes())
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "ORDINARY=value") || strings.Contains(strings.ToUpper(joined), "AWS_") || strings.Contains(strings.ToUpper(joined), "OP_") || strings.Contains(strings.ToUpper(joined), "AZURE_") || strings.Contains(joined, "secret") || strings.Contains(joined, "token") {
		t.Fatalf("unsafe child environment: %v", got)
	}
}

func TestShouldStripInheritedResolvedKeysFromChildEnvironment(t *testing.T) {
	got := safeChildEnvironment([]string{"PATH=/bin", "MY_API_KEY=stale", "my_api_key=duplicate", "OTHER=kept"}, nil, []string{"MY_API_KEY"})
	if strings.Join(got, "|") != "PATH=/bin|OTHER=kept" {
		t.Fatalf("environment=%v", got)
	}
}

func TestRegistryBindsAzureKeyVaultReference(t *testing.T) {
	ref, err := registry().Parse("azure-key-vault://myvault.vault.azure.net/MY-SECRET/MY_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Region != "myvault.vault.azure.net" || ref.Container != "MY-SECRET" || ref.Key != "MY_API_KEY" {
		t.Fatalf("ref=%+v", ref)
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

type cliAdapter struct {
	accesses, reads, writes, readCalls int
	value                              string
	read                               func(context.Context, []provider.Reference) (map[string]secret.Value, error)
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

func TestShouldReturnInvalidArgumentsErrorGivenNonPositiveTimeout(t *testing.T) {
	path := templateFile(t)
	for _, duration := range []string{"0s", "-1s", "invalid"} {
		_, err := executeWithRegistry(context.Background(), []string{"--template", path, "--timeout", duration, "check"}, cliRegistry(&cliAdapter{}))
		if err == nil || !strings.Contains(err.Error(), "invalid arguments") {
			t.Fatalf("duration=%q err=%v", duration, err)
		}
	}
}

func TestShouldValidateArgumentsBeforeReadingTemplate(t *testing.T) {
	code, err := executeWithRegistry(context.Background(), []string{"--template", "missing", "unknown"}, cliRegistry(&cliAdapter{}))
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
	_, err := executeWithRegistry(context.Background(), []string{"--template", path, "--timeout", "1ms", "sync"}, cliRegistry(adapter))
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
	code, err := executeWithRegistry(context.Background(), args, cliRegistry(adapter))
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
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "--timeout", "2s", "sync"}, cliRegistry(adapter)); err != nil {
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
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "sync"}, cliRegistry(adapter)); err != nil {
		t.Fatal(err)
	}
}

func TestShouldReportCompletedWriteGivenTimeoutDuringSync(t *testing.T) {
	adapter := &cliAdapter{write: func(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
		<-ctx.Done()
		return provider.Receipt{Completed: []string{writes[0].Environment}}, errors.New("remote provider leaked text")
	}}
	path := templateFile(t)
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	_, gotErr := executeWithRegistry(context.Background(), []string{"--template", path, "--timeout", "1ms", "sync", "--force"}, cliRegistry(adapter))
	os.Stdout = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if gotErr == nil || gotErr.Error() != "operation timed out" || string(output) != "VALUE: create\n" {
		t.Fatalf("output=%q err=%v", output, gotErr)
	}
}

func TestShouldRefuseToWriteGivenPendingChangeWithoutForceNonInteractively(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	// A pipe is never a character device, so this deterministically exercises
	// the non-interactive path regardless of whether the test runner's own
	// stdin happens to be a real terminal.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	_, err = executeWithRegistry(context.Background(), []string{"--template", path, "sync"}, cliRegistry(adapter))
	if err == nil || !strings.Contains(err.Error(), "--force") || adapter.writes != 0 {
		t.Fatalf("writes=%d err=%v", adapter.writes, err)
	}
}

func TestShouldWritePendingChangeGivenForceFlag(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	output := captureStdout(t, func() {
		if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "sync", "--force"}, cliRegistry(adapter)); err != nil {
			t.Fatal(err)
		}
	})
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
	output := captureStdout(t, func() {
		if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "sync"}, cliRegistry(adapter)); err != nil {
			t.Fatal(err)
		}
	})
	if adapter.writes != 0 || output != "VALUE: unchanged\n" {
		t.Fatalf("writes=%d output=%q", adapter.writes, output)
	}
}

func TestShouldPrintJSONResultGivenJSONFlag(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	output := captureStdout(t, func() {
		if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "sync", "--force", "--json"}, cliRegistry(adapter)); err != nil {
			t.Fatal(err)
		}
	})
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
	output := captureStdout(t, func() {
		if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "rollback", "--force"}, rollbackCliRegistry(adapter)); err != nil {
			t.Fatal(err)
		}
	})
	if adapter.rolledBack != 1 || output != "VALUE: reverted\n" {
		t.Fatalf("rolledBack=%d output=%q", adapter.rolledBack, output)
	}
}

func TestShouldRefuseRollbackWithoutForceNonInteractively(t *testing.T) {
	adapter := &rollbackCliAdapter{}
	path := templateFile(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	_, err = executeWithRegistry(context.Background(), []string{"--template", path, "rollback"}, rollbackCliRegistry(adapter))
	if err == nil || !strings.Contains(err.Error(), "--force") || adapter.rolledBack != 0 {
		t.Fatalf("rolledBack=%d err=%v", adapter.rolledBack, err)
	}
}

func TestShouldReportUnsupportedGivenProviderLacksRollback(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	output := captureStdout(t, func() {
		if code, err := executeWithRegistry(context.Background(), []string{"--template", path, "rollback", "--force"}, cliRegistry(adapter)); err == nil || code != 1 {
			t.Fatalf("code=%d err=%v", code, err)
		}
	})
	if output != "VALUE: unsupported\n" {
		t.Fatalf("output=%q", output)
	}
}

func TestShouldPrintRollbackJSONResultGivenJSONFlag(t *testing.T) {
	adapter := &rollbackCliAdapter{}
	path := templateFile(t)
	output := captureStdout(t, func() {
		if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "rollback", "--force", "--json"}, rollbackCliRegistry(adapter)); err != nil {
			t.Fatal(err)
		}
	})
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
func TestShouldSkipProviderAccessGivenCheckOrDryRunCommand(t *testing.T) {
	adapter := &cliAdapter{}
	providers := cliRegistry(adapter)
	path := templateFile(t)
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "check"}, providers); err != nil {
		t.Fatal(err)
	}
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "sync", "--dry-run"}, providers); err != nil {
		t.Fatal(err)
	}
	if adapter.accesses != 1 {
		t.Fatalf("provider accesses=%d", adapter.accesses)
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
	code, err := executeWithRegistry(context.Background(), args, providers)
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
		_, err := executeWithRegistry(context.Background(), args, cliRegistry(adapter))
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
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "check"}, cliRegistry(adapter)); err != nil {
		t.Fatal(err)
	}
	if _, err := executeWithRegistry(context.Background(), []string{"--template", "sync", "check"}, cliRegistry(adapter)); err == nil || err.Error() != "could not read secrets template" {
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
		output := captureStdout(t, func() {
			if _, err := executeWithRegistry(context.Background(), tc.args, cliRegistry(&cliAdapter{})); err != nil {
				t.Fatal(err)
			}
		})
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
		output := captureStdout(t, func() {
			if _, err := executeWithRegistry(context.Background(), tc.args, cliRegistry(&cliAdapter{})); err != nil {
				t.Fatalf("args=%v err=%v", tc.args, err)
			}
		})
		if !strings.Contains(output, tc.want) {
			t.Fatalf("args=%v output=%q want substring=%q", tc.args, output, tc.want)
		}
	}
}

func TestShouldReportUnknownFlagErrorBeforeCommandDiscoveryGivenInvalidGlobalFlag(t *testing.T) {
	_, err := executeWithRegistry(context.Background(), []string{"--foo", "bar", "check"}, cliRegistry(&cliAdapter{}))
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
	code, err := executeWithRegistry(context.Background(), args, cliRegistry(adapter))
	if err != nil || code != 0 || adapter.reads != 1 {
		t.Fatalf("code=%d reads=%d err=%v", code, adapter.reads, err)
	}
	if _, err := executeWithRegistry(context.Background(), []string{"run", "--template", "--", "/usr/bin/true"}, cliRegistry(&cliAdapter{})); err == nil || err.Error() != "run requires a command after --" {
		t.Fatalf("missing separator err=%v", err)
	}
}

func TestShouldAcceptCommandGivenLeadingDoubleDashSeparator(t *testing.T) {
	path := templateFile(t)
	t.Setenv("UNO_TEMPLATE", path)
	if _, err := executeWithRegistry(context.Background(), []string{"--", "check"}, cliRegistry(&cliAdapter{})); err != nil {
		t.Fatal(err)
	}
}

func TestShouldReturnUnknownCommandErrorGivenEmptyStringArgument(t *testing.T) {
	path := templateFile(t)
	_, err := executeWithRegistry(context.Background(), []string{"--template", path, "", "sync", "--dry-run"}, cliRegistry(&cliAdapter{}))
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
		output := captureStdout(t, func() {
			if _, err := executeWithRegistry(context.Background(), tc.args, cliRegistry(&cliAdapter{})); err != nil {
				t.Fatalf("args=%v err=%v", tc.args, err)
			}
		})
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
		_, err := executeWithRegistry(context.Background(), tc.args, cliRegistry(&cliAdapter{}))
		if err == nil || err.Error() != tc.want {
			t.Fatalf("args=%v err=%v want=%q", tc.args, err, tc.want)
		}
	}
}

func captureStdout(t *testing.T, action func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	action()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}
func TestShouldWriteEscapedSecretsFileWithRestrictedPermissionsGivenDevCommand(t *testing.T) {
	adapter := &cliAdapter{value: "line one\n\"$VALUE\"\\end"}
	providers := cliRegistry(adapter)
	temporary := t.TempDir()
	t.Chdir(temporary)
	if err := exec.CommandContext(t.Context(), "git", "init", "-q").Run(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".gitignore", []byte(".env.secrets*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := templateFile(t)
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "dev"}, providers); err != nil {
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
func TestShouldFailBeforeProviderAccessGivenMissingGitignoreOnDevCommand(t *testing.T) {
	adapter := &cliAdapter{}
	providers := cliRegistry(adapter)
	t.Chdir(t.TempDir())
	path := templateFile(t)
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "dev"}, providers); err == nil {
		t.Fatal("expected missing .gitignore failure")
	}
	if adapter.accesses != 0 || adapter.reads != 0 {
		t.Fatalf("accesses=%d reads=%d", adapter.accesses, adapter.reads)
	}
}

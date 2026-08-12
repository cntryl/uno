package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

func TestSafeChildEnvironmentStripsProviderCapabilities(t *testing.T) {
	got := safeChildEnvironment([]string{"PATH=/bin", "AWS_REGION=us-east-1", "AWS_PROFILE=admin", "AWS_SECRET_ACCESS_KEY=secret", "AWS_FOO_BAR=x", "OP_SERVICE_ACCOUNT_TOKEN=token", "ORDINARY=value"}, registry().CapabilityPrefixes())
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "ORDINARY=value") || strings.Contains(joined, "AWS_") || strings.Contains(joined, "OP_") || strings.Contains(joined, "secret") || strings.Contains(joined, "token") {
		t.Fatalf("unsafe child environment: %v", got)
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
	accesses, reads, writes int
	value                   string
	read                    func(context.Context, []provider.Reference) (map[string]secret.Value, error)
	write                   func(context.Context, []provider.Write) (provider.Receipt, error)
}

func (a *cliAdapter) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
	if a.read != nil {
		return a.read(ctx, refs)
	}
	out := make(map[string]secret.Value, len(refs))
	for _, r := range refs {
		a.reads++
		value := a.value
		if value == "" {
			value = "resolved"
		}
		out[r.Binding()] = secret.New(value)
	}
	return out, nil
}

func TestTimeoutRejectsNonPositiveDurations(t *testing.T) {
	path := templateFile(t)
	for _, duration := range []string{"0s", "-1s", "invalid"} {
		_, err := executeWithRegistry(context.Background(), []string{"--template", path, "--timeout", duration, "check"}, cliRegistry(&cliAdapter{}))
		if err == nil || !strings.Contains(err.Error(), "invalid arguments") {
			t.Fatalf("duration=%q err=%v", duration, err)
		}
	}
}

func TestBlockingProviderIsCanceledAndTimeoutIsRedacted(t *testing.T) {
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

func TestRunChildOutlivesProviderTimeout(t *testing.T) {
	adapter := &cliAdapter{}
	path := templateFile(t)
	code, err := executeWithRegistry(context.Background(), []string{"--template", path, "--timeout", "1ms", "run", "--", "/bin/sh", "-c", "sleep 0.03; test \"$VALUE\" = resolved"}, cliRegistry(adapter))
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestCustomTimeoutReachesProviderContext(t *testing.T) {
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

func TestDefaultTimeoutReachesProviderContext(t *testing.T) {
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

func TestTimeoutPreservesCompletedWriteReceipt(t *testing.T) {
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
	_, gotErr := executeWithRegistry(context.Background(), []string{"--template", path, "--timeout", "1ms", "sync"}, cliRegistry(adapter))
	os.Stdout = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if gotErr == nil || gotErr.Error() != "operation timed out" || string(output) != "VALUE: synced\n" {
		t.Fatalf("output=%q err=%v", output, gotErr)
	}
}
func (a *cliAdapter) WriteMany(ctx context.Context, w []provider.Write) (provider.Receipt, error) {
	a.writes++
	if a.write != nil {
		return a.write(ctx, w)
	}
	return provider.Receipt{Completed: []string{w[0].Environment}}, nil
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
func TestCheckAndDryRunPerformNoProviderAccess(t *testing.T) {
	adapter := &cliAdapter{}
	providers := cliRegistry(adapter)
	path := templateFile(t)
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "check"}, providers); err != nil {
		t.Fatal(err)
	}
	if _, err := executeWithRegistry(context.Background(), []string{"--template", path, "sync", "--dry-run"}, providers); err != nil {
		t.Fatal(err)
	}
	if adapter.accesses != 0 {
		t.Fatalf("provider accesses=%d", adapter.accesses)
	}
}
func TestRunReadsWithoutWritingAndPreservesExitStatus(t *testing.T) {
	adapter := &cliAdapter{}
	providers := cliRegistry(adapter)
	path := templateFile(t)
	code, err := executeWithRegistry(context.Background(), []string{"--template", path, "run", "--", "/bin/sh", "-c", "test \"$VALUE\" = resolved; exit 7"}, providers)
	if err != nil || code != 7 || adapter.reads != 1 || adapter.writes != 0 {
		t.Fatalf("code=%d reads=%d writes=%d err=%v", code, adapter.reads, adapter.writes, err)
	}
}
func TestDevWritesSortedEscapedFileWithRestrictedPermissions(t *testing.T) {
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
	if info.Mode().Perm() != 0o600 || adapter.reads != 1 || adapter.writes != 0 {
		t.Fatalf("mode=%o reads=%d writes=%d", info.Mode().Perm(), adapter.reads, adapter.writes)
	}
}
func TestDevRequiresGitignoreBeforeProviderAccess(t *testing.T) {
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

package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
	tpl "github.com/cntryl/uno/internal/core/template"
)

type fakeFactory struct{ adapter *fakeAdapter }

func (f fakeFactory) Parse(raw string) (provider.Reference, error) {
	parts := stringsSplit(raw)
	return provider.Reference{Scheme: parts[0], Container: parts[1], Key: parts[2]}, nil
}
func stringsSplit(raw string) []string {
	i := 0
	for ; i+2 < len(raw); i++ {
		if raw[i:i+3] == "://" {
			break
		}
	}
	rest := raw[i+3:]
	slash := -1
	for j := range rest {
		if rest[j] == '/' {
			slash = j
			break
		}
	}
	if slash < 0 {
		return []string{raw[:i], rest, ""}
	}
	return []string{raw[:i], rest[:slash], rest[slash+1:]}
}
func (f fakeFactory) Adapter(context.Context, provider.Reference) (provider.Adapter, error) {
	return f.adapter, nil
}

type fakeAdapter struct {
	reads    []string
	writes   [][]provider.Write
	values   map[string]string
	failRead string
}

func (f *fakeAdapter) Read(_ context.Context, r provider.Reference) (secret.Value, error) {
	f.reads = append(f.reads, r.Binding())
	if r.Key == f.failRead {
		return secret.Value{}, errors.New("remote leaked secret")
	}
	return secret.New(f.values[r.Key]), nil
}
func (f *fakeAdapter) ReadMany(ctx context.Context, refs []provider.Reference) ([]secret.Value, error) {
	out := make([]secret.Value, 0, len(refs))
	for _, r := range refs {
		v, err := f.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (f *fakeAdapter) WriteMany(_ context.Context, w []provider.Write) (provider.Receipt, error) {
	f.writes = append(f.writes, w)
	out := make([]string, 0, len(w))
	for _, x := range w {
		out = append(out, x.Environment)
	}
	return provider.Receipt{Completed: out}, nil
}
func planFor(t *testing.T, text string, adapter *fakeAdapter) *Plan {
	t.Helper()
	file, err := tpl.ParseEnv(text, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	registry := provider.NewRegistry()
	registry.Register("fake", fakeFactory{adapter})
	p, err := Bind(file, registry)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestSyncResolvesAllSourcesBeforeGroupedWrites(t *testing.T) {
	adapter := &fakeAdapter{values: map[string]string{"a": "one", "b": "two"}}
	p := planFor(t, "A=fake://source/a -> fake://target/a\nB=fake://source/b -> fake://target/b\n", adapter)
	receipt, err := Sync(context.Background(), p)
	if err != nil || len(adapter.reads) != 2 || len(adapter.writes) != 1 || fmt.Sprint(receipt.Completed) != "[A B]" {
		t.Fatalf("receipt=%#v reads=%v writes=%v err=%v", receipt, adapter.reads, adapter.writes, err)
	}
}
func TestSourceFailurePreventsEveryWriteAndRedacts(t *testing.T) {
	adapter := &fakeAdapter{values: map[string]string{"a": "one"}, failRead: "b"}
	p := planFor(t, "A=fake://s/a -> fake://d/a\nB=fake://s/b -> fake://d/b\n", adapter)
	_, err := Sync(context.Background(), p)
	if err == nil || len(adapter.writes) != 0 || stringsContains(err.Error(), "leaked") {
		t.Fatalf("writes=%v err=%v", adapter.writes, err)
	}
}
func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
func TestBindRejectsDuplicateAndBlobKeyMix(t *testing.T) {
	adapter := &fakeAdapter{}
	for _, input := range []string{"A=fake://s/a -> fake://d/x\nB=fake://s/b -> fake://d/x\n", "A=fake://s/a -> fake://d\nB=fake://s/b -> fake://d/x\n"} {
		file, _ := tpl.ParseEnv(input, func(string) (string, bool) { return "", false })
		registry := provider.NewRegistry()
		registry.Register("fake", fakeFactory{adapter})
		if _, err := Bind(file, registry); err == nil {
			t.Fatalf("expected invalid bindings")
		}
	}
}

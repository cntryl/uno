package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	result   func([]provider.Reference) map[string]secret.Value
}

func (f *fakeAdapter) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
	_ = ctx
	if f.result != nil {
		return f.result(refs), nil
	}
	out := make(map[string]secret.Value, len(refs))
	for _, r := range refs {
		f.reads = append(f.reads, r.Binding())
		if r.Key == f.failRead {
			return nil, errors.New("remote leaked secret")
		}
		out[r.Binding()] = secret.New(f.values[r.Key])
	}
	return out, nil
}

func TestShouldReturnValuesKeyedByBindingGivenDuplicateSourceReferences(t *testing.T) {
	adapter := &fakeAdapter{result: func(refs []provider.Reference) map[string]secret.Value {
		if len(refs) != 2 {
			t.Fatalf("refs=%d", len(refs))
		}
		return map[string]secret.Value{refs[1].Binding(): secret.New("two"), refs[0].Binding(): secret.New("one")}
	}}
	p := planFor(t, "A=fake://s/a -> fake://d/a\nB=fake://s/b -> fake://d/b\nC=fake://s/a -> fake://d/c\n", adapter)
	values, err := Resolve(context.Background(), p)
	if err != nil || values["A"].Reveal() != "one" || values["B"].Reveal() != "two" || values["C"].Reveal() != "one" {
		t.Fatalf("values=%v err=%v", values, err)
	}
	secret.DestroyMap(values)
}

func TestShouldFailWithInvalidStateGivenMissingOrUnexpectedResultKeys(t *testing.T) {
	for _, result := range []func([]provider.Reference) map[string]secret.Value{
		func([]provider.Reference) map[string]secret.Value { return map[string]secret.Value{} },
		func(refs []provider.Reference) map[string]secret.Value {
			return map[string]secret.Value{refs[0].Binding(): secret.New("one"), "unexpected": secret.New("leak")}
		},
	} {
		adapter := &fakeAdapter{result: result}
		p := planFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
		if _, err := Sync(context.Background(), p); err == nil || len(adapter.writes) != 0 || !stringsContains(err.Error(), "InvalidState") {
			t.Fatalf("writes=%v err=%v", adapter.writes, err)
		}
	}
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
func TestShouldGroupWritesAfterResolvingAllSourcesGivenMultipleBindings(t *testing.T) {
	adapter := &fakeAdapter{values: map[string]string{"a": "one", "b": "two"}}
	p := planFor(t, "A=fake://source/a -> fake://target/a\nB=fake://source/b -> fake://target/b\n", adapter)
	receipt, err := Sync(context.Background(), p)
	if err != nil || len(adapter.reads) != 2 || len(adapter.writes) != 1 || fmt.Sprint(receipt.Completed) != "[A B]" {
		t.Fatalf("receipt=%#v reads=%v writes=%v err=%v", receipt, adapter.reads, adapter.writes, err)
	}
}
func TestShouldPreventWritesAndRedactErrorGivenSourceReadFailure(t *testing.T) {
	adapter := &fakeAdapter{values: map[string]string{"a": "one"}, failRead: "b"}
	p := planFor(t, "A=fake://s/a -> fake://d/a\nB=fake://s/b -> fake://d/b\n", adapter)
	_, err := Sync(context.Background(), p)
	if err == nil || len(adapter.writes) != 0 || stringsContains(err.Error(), "leaked") {
		t.Fatalf("writes=%v err=%v", adapter.writes, err)
	}
}

type concurrentAdapter struct {
	mu           sync.Mutex
	readStarted  int
	writeStarted int
	readRelease  chan struct{}
	writeRelease chan struct{}
}

func (a *concurrentAdapter) ReadMany(_ context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
	a.mu.Lock()
	a.readStarted++
	if a.readStarted == 2 {
		close(a.readRelease)
	}
	a.mu.Unlock()
	select {
	case <-a.readRelease:
	case <-time.After(time.Second):
		return nil, errors.New("source groups were sequential")
	}
	return map[string]secret.Value{refs[0].Binding(): secret.New("value")}, nil
}

func (a *concurrentAdapter) WriteMany(_ context.Context, writes []provider.Write) (provider.Receipt, error) {
	a.mu.Lock()
	a.writeStarted++
	if a.writeStarted == 2 {
		close(a.writeRelease)
	}
	a.mu.Unlock()
	select {
	case <-a.writeRelease:
	case <-time.After(time.Second):
		return provider.Receipt{}, errors.New("destination groups were sequential")
	}
	return provider.Receipt{Completed: provider.Environments(writes)}, nil
}

type concurrentFactory struct{ adapter *concurrentAdapter }

func (f concurrentFactory) Parse(raw string) (provider.Reference, error) {
	parts := stringsSplit(raw)
	return provider.Reference{Scheme: parts[0], Container: parts[1], Key: parts[2]}, nil
}
func (f concurrentFactory) Adapter(context.Context, provider.Reference) (provider.Adapter, error) {
	return f.adapter, nil
}

func TestShouldRunIndependentGroupsConcurrentlyGivenMultipleProviders(t *testing.T) {
	adapter := &concurrentAdapter{readRelease: make(chan struct{}), writeRelease: make(chan struct{})}
	file, err := tpl.ParseEnv("A=parallel://s1/a -> parallel://d1/a\nB=parallel://s2/b -> parallel://d2/b\n", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	registry := provider.NewRegistry()
	registry.Register("parallel", concurrentFactory{adapter})
	plan, err := Bind(file, registry)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := Sync(context.Background(), plan)
	if err != nil || fmt.Sprint(receipt.Completed) != "[A B]" {
		t.Fatalf("receipt=%v err=%v", receipt, err)
	}
}
func TestShouldBoundConcurrencyGivenMoreTasksThanTheLimit(t *testing.T) {
	const n = maxConcurrentOperations * 3
	var inFlight, peak int32
	runLimited(n, func(int) {
		current := atomic.AddInt32(&inFlight, 1)
		for {
			observed := atomic.LoadInt32(&peak)
			if current <= observed || atomic.CompareAndSwapInt32(&peak, observed, current) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
	})
	if peak > maxConcurrentOperations {
		t.Fatalf("peak concurrency=%d want<=%d", peak, maxConcurrentOperations)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency=%d, expected genuine parallelism below the cap", peak)
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
func TestShouldRejectBindGivenDuplicateDestinationOrBlobKeyMix(t *testing.T) {
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

// diffAdapter is a minimal store-backed fake: ReadMany succeeds only for
// bindings present in values, and fails with InvalidBinding otherwise
// (modeling "this destination doesn't exist yet"). This lets diff/sync tests
// control the source and destination sides of a mapping independently by
// giving them distinct containers.
type diffAdapter struct {
	values map[string]string
	writes [][]provider.Write
}

func (a *diffAdapter) ReadMany(_ context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
	out := make(map[string]secret.Value, len(refs))
	for _, r := range refs {
		value, ok := a.values[r.Binding()]
		if !ok {
			return nil, &provider.Error{Kind: provider.InvalidBinding}
		}
		out[r.Binding()] = secret.New(value)
	}
	return out, nil
}
func (a *diffAdapter) WriteMany(_ context.Context, w []provider.Write) (provider.Receipt, error) {
	a.writes = append(a.writes, w)
	out := make([]string, 0, len(w))
	for _, x := range w {
		out = append(out, x.Environment)
	}
	return provider.Receipt{Completed: out}, nil
}

type diffFactory struct{ adapter *diffAdapter }

func (f diffFactory) Parse(raw string) (provider.Reference, error) {
	parts := stringsSplit(raw)
	return provider.Reference{Scheme: parts[0], Container: parts[1], Key: parts[2]}, nil
}
func (f diffFactory) Adapter(context.Context, provider.Reference) (provider.Adapter, error) {
	return f.adapter, nil
}

func diffPlanFor(t *testing.T, text string, adapter *diffAdapter) *Plan {
	t.Helper()
	file, err := tpl.ParseEnv(text, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	registry := provider.NewRegistry()
	registry.Register("fake", diffFactory{adapter})
	p, err := Bind(file, registry)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func destinationBinding(container, key string) string {
	return provider.Reference{Scheme: "fake", Container: container, Key: key}.Binding()
}

func TestShouldReportUnchangedGivenDestinationAlreadyMatchesSource(t *testing.T) {
	adapter := &diffAdapter{values: map[string]string{
		destinationBinding("s", "a"): "one",
		destinationBinding("d", "a"): "one",
	}}
	p := diffPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	changes, err := Diff(context.Background(), p)
	if err != nil || len(changes) != 1 || changes[0] != (Change{Environment: "A", Kind: Unchanged}) || len(adapter.writes) != 0 {
		t.Fatalf("changes=%v writes=%v err=%v", changes, adapter.writes, err)
	}
}

func TestShouldReportUpdateGivenDestinationValueDiffersFromSource(t *testing.T) {
	adapter := &diffAdapter{values: map[string]string{
		destinationBinding("s", "a"): "new",
		destinationBinding("d", "a"): "old",
	}}
	p := diffPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	changes, err := Diff(context.Background(), p)
	if err != nil || len(changes) != 1 || changes[0] != (Change{Environment: "A", Kind: Update}) {
		t.Fatalf("changes=%v err=%v", changes, err)
	}
}

func TestShouldReportCreateGivenDestinationDoesNotExistYet(t *testing.T) {
	adapter := &diffAdapter{values: map[string]string{destinationBinding("s", "a"): "new"}}
	p := diffPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	changes, err := Diff(context.Background(), p)
	if err != nil || len(changes) != 1 || changes[0] != (Change{Environment: "A", Kind: Create}) {
		t.Fatalf("changes=%v err=%v", changes, err)
	}
}

func TestShouldSkipWriteAndConfirmGivenEveryMappingUnchanged(t *testing.T) {
	adapter := &diffAdapter{values: map[string]string{
		destinationBinding("s", "a"): "one",
		destinationBinding("d", "a"): "one",
	}}
	p := diffPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	confirmCalled := false
	changes, receipt, err := SyncChanged(context.Background(), p, func([]Change) (bool, error) {
		confirmCalled = true
		return true, nil
	})
	if err != nil || len(changes) != 1 || changes[0].Kind != Unchanged || len(receipt.Completed) != 0 || len(adapter.writes) != 0 || confirmCalled {
		t.Fatalf("changes=%v receipt=%v writes=%v confirmCalled=%v err=%v", changes, receipt, adapter.writes, confirmCalled, err)
	}
}

func TestShouldWriteOnlyPendingMappingsGivenMixedChanges(t *testing.T) {
	adapter := &diffAdapter{values: map[string]string{
		destinationBinding("s", "a"): "one",
		destinationBinding("d", "a"): "one", // A: unchanged
		destinationBinding("s", "b"): "new", // B: create (no destination entry)
	}}
	p := diffPlanFor(t, "A=fake://s/a -> fake://d/a\nB=fake://s/b -> fake://d/b\n", adapter)
	var changesAtConfirm []Change
	changes, receipt, err := SyncChanged(context.Background(), p, func(pending []Change) (bool, error) {
		changesAtConfirm = pending
		return true, nil
	})
	if err != nil || fmt.Sprint(receipt.Completed) != "[B]" || len(changesAtConfirm) != 1 || changesAtConfirm[0].Environment != "B" {
		t.Fatalf("changes=%v receipt=%v confirmed=%v err=%v", changes, receipt, changesAtConfirm, err)
	}
	if len(adapter.writes) != 1 || len(adapter.writes[0]) != 1 || adapter.writes[0][0].Environment != "B" {
		t.Fatalf("writes=%v", adapter.writes)
	}
}

func TestShouldAbortWithoutWritingGivenConfirmDeclines(t *testing.T) {
	adapter := &diffAdapter{values: map[string]string{destinationBinding("s", "a"): "new"}}
	p := diffPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	_, receipt, err := SyncChanged(context.Background(), p, func([]Change) (bool, error) { return false, nil })
	if err == nil || len(receipt.Completed) != 0 || len(adapter.writes) != 0 {
		t.Fatalf("receipt=%v writes=%v err=%v", receipt, adapter.writes, err)
	}
}

func TestShouldPropagateConfirmErrorWithoutWriting(t *testing.T) {
	adapter := &diffAdapter{values: map[string]string{destinationBinding("s", "a"): "new"}}
	p := diffPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	sentinel := errors.New("confirmation source unavailable")
	_, receipt, err := SyncChanged(context.Background(), p, func([]Change) (bool, error) { return false, sentinel })
	if !errors.Is(err, sentinel) || len(receipt.Completed) != 0 || len(adapter.writes) != 0 {
		t.Fatalf("receipt=%v writes=%v err=%v", receipt, adapter.writes, err)
	}
}

func TestShouldWriteWithoutConfirmGivenNilConfirmCallback(t *testing.T) {
	adapter := &diffAdapter{values: map[string]string{destinationBinding("s", "a"): "new"}}
	p := diffPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	_, receipt, err := SyncChanged(context.Background(), p, nil)
	if err != nil || fmt.Sprint(receipt.Completed) != "[A]" {
		t.Fatalf("receipt=%v err=%v", receipt, err)
	}
}

type rollbackCapableAdapter struct {
	diffAdapter

	rolledBack []provider.Reference
	failWith   error
}

func (a *rollbackCapableAdapter) Rollback(_ context.Context, ref provider.Reference) error {
	a.rolledBack = append(a.rolledBack, ref)
	return a.failWith
}

type rollbackFactory struct{ adapter provider.Adapter }

func (f rollbackFactory) Parse(raw string) (provider.Reference, error) {
	parts := stringsSplit(raw)
	return provider.Reference{Scheme: parts[0], Container: parts[1], Key: parts[2]}, nil
}
func (f rollbackFactory) Adapter(context.Context, provider.Reference) (provider.Adapter, error) {
	return f.adapter, nil
}

func rollbackPlanFor(t *testing.T, text string, adapter provider.Adapter) *Plan {
	t.Helper()
	file, err := tpl.ParseEnv(text, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	registry := provider.NewRegistry()
	registry.Register("fake", rollbackFactory{adapter})
	p, err := Bind(file, registry)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestShouldReportRevertedGivenAdapterSupportsRollback(t *testing.T) {
	adapter := &rollbackCapableAdapter{}
	p := rollbackPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	results, err := Rollback(context.Background(), p)
	if err != nil || len(results) != 1 || results[0] != (RollbackResult{Environment: "A", Status: Reverted}) || len(adapter.rolledBack) != 1 {
		t.Fatalf("results=%v rolledBack=%v err=%v", results, adapter.rolledBack, err)
	}
}

func TestShouldReportUnsupportedGivenAdapterDoesNotImplementRollbacker(t *testing.T) {
	adapter := &diffAdapter{}
	p := rollbackPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	results, err := Rollback(context.Background(), p)
	if err != nil || len(results) != 1 || results[0].Status != Unsupported || results[0].Environment != "A" {
		t.Fatalf("results=%v err=%v", results, err)
	}
}

func TestShouldReportFailedGivenRollbackReturnsError(t *testing.T) {
	adapter := &rollbackCapableAdapter{failWith: &provider.Error{Kind: provider.InvalidState, Detail: "no previous version"}}
	p := rollbackPlanFor(t, "A=fake://s/a -> fake://d/a\n", adapter)
	results, err := Rollback(context.Background(), p)
	if err != nil || len(results) != 1 || results[0].Status != Failed || results[0].Environment != "A" || results[0].Detail == "" {
		t.Fatalf("results=%v err=%v", results, err)
	}
}

func TestShouldCallRollbackOncePerDistinctDestinationContainer(t *testing.T) {
	adapter := &rollbackCapableAdapter{}
	p := rollbackPlanFor(t, "A=fake://s/a -> fake://d/x\nB=fake://s/b -> fake://d/y\n", adapter)
	results, err := Rollback(context.Background(), p)
	if err != nil || len(results) != 2 || len(adapter.rolledBack) != 1 {
		t.Fatalf("results=%v rolledBack=%v err=%v", results, adapter.rolledBack, err)
	}
}

func TestShouldReportActionableErrorMessagesGivenInvalidReferencesOrDestinations(t *testing.T) {
	adapter := &fakeAdapter{}
	registry := provider.NewRegistry()
	registry.Register("fake", fakeFactory{adapter})

	file, _ := tpl.ParseEnv("A=unknown://source/a -> fake://d/a\n", func(string) (string, bool) { return "", false })
	if _, err := Bind(file, registry); err == nil || err.Error() != "line 1: invalid source reference: unknown provider scheme" {
		t.Fatalf("source err=%v", err)
	}

	file, _ = tpl.ParseEnv("A=fake://s/a -> fake://d/x\nB=fake://s/b -> fake://d/x\n", func(string) (string, bool) { return "", false })
	if _, err := Bind(file, registry); err == nil || err.Error() != "line 2: destination duplicates line 1 (A)" {
		t.Fatalf("duplicate err=%v", err)
	}

	file, _ = tpl.ParseEnv("A=fake://s/a -> fake://d\nB=fake://s/b -> fake://d/x\n", func(string) (string, bool) { return "", false })
	if _, err := Bind(file, registry); err == nil || err.Error() != "line 2: destination mixes blob and keyed writes with line 1 (A)" {
		t.Fatalf("mixed err=%v", err)
	}
}

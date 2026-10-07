package onepassword

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	op "github.com/1password/onepassword-sdk-go"
)

// A blocked desktop request models an authorization prompt or session renewal.
// Other requests must wait for it before entering the same native SDK core.
type blockingSDK struct {
	op.ItemsAPI

	entered chan string
	release chan struct{}
}

func (f *blockingSDK) call(name string) { f.entered <- name; <-f.release }
func (f *blockingSDK) Get(context.Context, string, string) (op.Item, error) {
	f.call("get")
	return op.Item{}, nil
}
func (f *blockingSDK) List(context.Context, string, ...op.ItemListFilter) ([]op.ItemOverview, error) {
	f.call("list")
	return nil, nil
}
func (f *blockingSDK) Put(context.Context, op.Item) (op.Item, error) {
	f.call("put")
	return op.Item{}, nil
}
func (f *blockingSDK) Files() op.ItemsFilesAPI { return &blockingFiles{sdk: f} }

type blockingFiles struct {
	op.ItemsFilesAPI

	sdk *blockingSDK
}

func (f *blockingFiles) Read(context.Context, string, string, op.FileAttributes) ([]byte, error) {
	f.sdk.call("file")
	return nil, nil
}

type blockingVaults struct {
	op.VaultsAPI

	sdk *blockingSDK
}

func (f *blockingVaults) List(context.Context, ...op.VaultListParams) ([]op.VaultOverview, error) {
	f.sdk.call("vaults")
	return nil, nil
}

func TestShouldSerializeDesktopSDKCallsAcrossClients(t *testing.T) {
	fake := &blockingSDK{entered: make(chan string, 10), release: make(chan struct{})}
	client := &op.Client{ItemsAPI: fake, VaultsAPI: &blockingVaults{sdk: fake}}
	build := func(ctx context.Context, _ ...op.ClientOption) (*op.Client, error) { return client, ctx.Err() }
	first, err := newSDKAPI(context.Background(), "", "account", build)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newSDKAPI(context.Background(), "", "account", build)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() { _, _ = first.GetItem(context.Background(), "vault", "item") })
	awaitSDKCall(t, fake)
	workers.Go(func() { _, _ = second.ListVaults(context.Background()) })
	workers.Go(func() { _, _ = second.ListItems(context.Background(), "vault") })
	workers.Go(func() { _, _ = second.GetItem(context.Background(), "vault", "item") })
	workers.Go(func() { _, _ = second.PutItem(context.Background(), op.Item{}) })
	workers.Go(func() { _, _ = second.ReadFile(context.Background(), "vault", "item", op.FileAttributes{}) })
	workers.Go(func() {
		_, _ = newSDKAPI(context.Background(), "", "account", func(context.Context, ...op.ClientOption) (*op.Client, error) {
			fake.call("init")
			return client, nil
		})
	})
	select {
	case <-fake.entered:
		t.Error("desktop SDK calls overlapped")
	case <-time.After(100 * time.Millisecond):
	}
	close(fake.release)
	workers.Wait()
	if len(fake.entered) != 6 {
		t.Errorf("SDK calls=%d, want 6", len(fake.entered))
	}
}

func TestShouldKeepServiceAccountSDKIndependentOfDesktopAuthorization(t *testing.T) {
	fake := &blockingSDK{entered: make(chan string, 10), release: make(chan struct{})}
	client := &op.Client{ItemsAPI: fake}
	build := func(ctx context.Context, _ ...op.ClientOption) (*op.Client, error) { return client, ctx.Err() }
	desktop, err := newSDKAPI(context.Background(), "", "account", build)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() { _, _ = desktop.GetItem(context.Background(), "vault", "item") })
	awaitSDKCall(t, fake)
	workers.Go(func() {
		service, buildErr := newSDKAPI(context.Background(), "token", "account", build)
		if buildErr != nil {
			t.Error(buildErr)
			return
		}
		_, _ = service.GetItem(context.Background(), "vault", "item")
	})
	awaitSDKCall(t, fake)
	close(fake.release)
	workers.Wait()
}

func TestShouldSkipCanceledSDKRequestAfterWaitingForDesktopAuthorization(t *testing.T) {
	fake := &blockingSDK{entered: make(chan string, 10), release: make(chan struct{})}
	client := &op.Client{ItemsAPI: fake}
	api, err := newSDKAPI(context.Background(), "", "account", func(ctx context.Context, _ ...op.ClientOption) (*op.Client, error) { return client, ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() { _, _ = api.GetItem(context.Background(), "vault", "item") })
	awaitSDKCall(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	var gotErr error
	workers.Go(func() { _, gotErr = api.PutItem(ctx, op.Item{}) })
	cancel()
	close(fake.release)
	workers.Wait()
	if !errors.Is(gotErr, context.Canceled) {
		t.Errorf("error=%v, want cancellation", gotErr)
	}
	if len(fake.entered) != 0 {
		t.Errorf("canceled request reached SDK")
	}
}

func awaitSDKCall(t *testing.T, fake *blockingSDK) {
	t.Helper()
	select {
	case <-fake.entered:
	case <-time.After(5 * time.Second):
		close(fake.release)
		t.Fatal("SDK call did not enter")
	}
}

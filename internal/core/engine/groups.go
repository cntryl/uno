package engine

import (
	"context"
	"sort"
	"sync"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type sourceGroup struct {
	reference provider.Reference
	mappings  []Mapping
}

// groupByReference groups mappings by the container that selector picks out
// of each one (Source or Destination), sorted by container key for
// deterministic iteration order.
func groupByReference(mappings []Mapping, selector func(Mapping) provider.Reference) []sourceGroup {
	byContainer := make(map[string]*sourceGroup)
	keys := make([]string, 0)
	for _, mapping := range mappings {
		ref := selector(mapping)
		key := containerKey(ref)
		if byContainer[key] == nil {
			byContainer[key] = &sourceGroup{reference: ref}
			keys = append(keys, key)
		}
		byContainer[key].mappings = append(byContainer[key].mappings, mapping)
	}
	sort.Strings(keys)
	groups := make([]sourceGroup, 0, len(keys))
	for _, key := range keys {
		groups = append(groups, *byContainer[key])
	}
	return groups
}

func groupSources(mappings []Mapping) []sourceGroup {
	return groupByReference(mappings, func(m Mapping) provider.Reference { return m.Source })
}

func groupDestinationContainers(mappings []Mapping) []sourceGroup {
	return groupByReference(mappings, func(m Mapping) provider.Reference { return m.Destination })
}

type destinationGroup struct {
	reference provider.Reference
	writes    []provider.Write
}

func groupDestinations(mappings []Mapping, values map[string]secret.Value) []destinationGroup {
	byContainer := make(map[string]*destinationGroup)
	keys := make([]string, 0)
	for _, mapping := range mappings {
		key := containerKey(mapping.Destination)
		if byContainer[key] == nil {
			byContainer[key] = &destinationGroup{reference: mapping.Destination}
			keys = append(keys, key)
		}
		byContainer[key].writes = append(byContainer[key].writes, provider.Write{
			Environment: mapping.Environment,
			Reference:   mapping.Destination,
			Value:       values[mapping.Environment],
		})
	}
	sort.Strings(keys)
	groups := make([]destinationGroup, 0, len(keys))
	for _, key := range keys {
		group := *byContainer[key]
		provider.SortedWrites(group.writes)
		groups = append(groups, group)
	}
	return groups
}

type adapterEntry struct {
	once    sync.Once
	adapter provider.Adapter
	err     error
}

type adapterCache struct {
	registry *provider.Registry
	entries  map[string]*adapterEntry
	mu       sync.Mutex
}

func newAdapterCache(registry *provider.Registry) *adapterCache {
	return &adapterCache{registry: registry, entries: make(map[string]*adapterEntry)}
}

// get builds the adapter for ref's key at most once, but never holds the
// cache's mutex while the (network-bound) registry.Adapter call runs, so
// unrelated provider/region groups can be built concurrently instead of
// serializing on one lock.
func (c *adapterCache) get(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	key := ref.AdapterKey
	if key == "" {
		key = ref.Scheme + "\x00" + ref.Region
	}
	c.mu.Lock()
	entry := c.entries[key]
	if entry == nil {
		entry = &adapterEntry{}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		entry.adapter, entry.err = c.registry.Adapter(ctx, ref)
	})
	return entry.adapter, entry.err
}

func containerKey(ref provider.Reference) string {
	return ref.Scheme + "\x00" + ref.Region + "\x00" + ref.Container
}

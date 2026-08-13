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

func groupSources(mappings []Mapping) []sourceGroup {
	byContainer := make(map[string]*sourceGroup)
	keys := make([]string, 0)
	for _, mapping := range mappings {
		key := containerKey(mapping.Source)
		if byContainer[key] == nil {
			byContainer[key] = &sourceGroup{reference: mapping.Source}
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

type adapterCache struct {
	registry *provider.Registry
	values   map[string]provider.Adapter
	mu       sync.Mutex
}

func newAdapterCache(registry *provider.Registry) *adapterCache {
	return &adapterCache{registry: registry, values: make(map[string]provider.Adapter)}
}

func (c *adapterCache) get(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := ref.AdapterKey
	if key == "" {
		key = ref.Scheme + "\x00" + ref.Region
	}
	if adapter := c.values[key]; adapter != nil {
		return adapter, nil
	}
	adapter, err := c.registry.Adapter(ctx, ref)
	if err == nil {
		c.values[key] = adapter
	}
	return adapter, err
}

func containerKey(ref provider.Reference) string {
	return ref.Scheme + "\x00" + ref.Region + "\x00" + ref.Container
}

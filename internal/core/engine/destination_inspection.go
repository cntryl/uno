package engine

import (
	"context"
	"sort"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type destinationInspectionResult struct {
	changes []Change
	err     error
}

func inspectDestinations(ctx context.Context, plan *Plan, desiredValues map[string]secret.Value, adapters *adapterCache) ([]Change, error) {
	groups := groupDestinationContainers(plan.Mappings)
	groupResults := make([]destinationInspectionResult, len(groups))

	runLimited(len(groups), func(groupIndex int) {
		groupResults[groupIndex] = inspectDestinationGroup(ctx, groups[groupIndex], desiredValues, adapters)
	})

	changes := make([]Change, 0, len(plan.Mappings))
	for _, groupResult := range groupResults {
		if groupResult.err != nil {
			return changes, groupResult.err
		}
		changes = append(changes, groupResult.changes...)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Environment < changes[j].Environment })
	return changes, nil
}

func inspectDestinationGroup(ctx context.Context, group sourceGroup, desiredValues map[string]secret.Value, adapters *adapterCache) destinationInspectionResult {
	adapter, err := adapters.get(ctx, group.reference)
	if err != nil {
		return destinationInspectionFailure(err)
	}

	destinationReferences := make([]provider.Reference, 0, len(group.mappings))
	for _, mapping := range group.mappings {
		destinationReferences = append(destinationReferences, mapping.Destination)
	}

	readResults, err := readDestinations(ctx, adapter, destinationReferences)
	if err != nil {
		provider.DestroyReadResults(readResults)
		return destinationInspectionFailure(err)
	}
	defer provider.DestroyReadResults(readResults)

	if !validDestinationResults(destinationReferences, readResults) {
		return destinationInspectionFailure(&provider.Error{Kind: provider.InvalidState})
	}

	changes := make([]Change, 0, len(group.mappings))
	for _, mapping := range group.mappings {
		currentSecret := readResults[mapping.Destination.Binding()]
		changes = append(changes, Change{
			Environment: mapping.Environment,
			Kind:        classifyDestination(currentSecret, desiredValues[mapping.Environment]),
		})
	}
	return destinationInspectionResult{changes: changes}
}

func readDestinations(ctx context.Context, adapter provider.Adapter, references []provider.Reference) (map[string]provider.ReadResult, error) {
	if destinationReader, ok := adapter.(provider.DestinationReader); ok {
		return destinationReader.ReadDestinations(ctx, references)
	}
	return adapter.ReadMany(ctx, references)
}

func validDestinationResults(references []provider.Reference, readResults map[string]provider.ReadResult) bool {
	if len(readResults) != len(references) {
		return false
	}
	for _, reference := range references {
		if _, ok := readResults[reference.Binding()]; !ok {
			return false
		}
	}
	return true
}

func classifyDestination(currentSecret provider.ReadResult, desiredValue secret.Value) ChangeKind {
	if !currentSecret.Found {
		return Create
	}
	if currentSecret.Value.Reveal() == desiredValue.Reveal() {
		return Unchanged
	}
	return Update
}

func destinationInspectionFailure(err error) destinationInspectionResult {
	return destinationInspectionResult{err: safeOperationError("inspect", err)}
}

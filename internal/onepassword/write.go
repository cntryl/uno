package onepassword

import (
	"context"
	"errors"
	"fmt"
	"sort"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cntryl/uno/internal/core/provider"
)

const conflictRetries = 3

type versionConflict interface{ VersionConflict() bool }

func (a *Adapter) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}
	provider.SortedWrites(writes)
	for attempt := 0; attempt <= conflictRetries; attempt++ {
		item, err := a.load(ctx, writes[0].Reference)
		if err != nil {
			return provider.Receipt{}, err
		}
		if err := validateDestination(item); err != nil {
			return provider.Receipt{}, err
		}
		if err := applyWrites(item, writes); err != nil {
			return provider.Receipt{}, err
		}
		if _, err := a.mutation.PutItem(ctx, *item); err == nil {
			return provider.Receipt{Completed: environments(writes)}, nil
		} else {
			var conflict versionConflict
			if !errors.As(err, &conflict) || !conflict.VersionConflict() {
				return provider.Receipt{}, remote()
			}
		}
	}
	return provider.Receipt{}, remote()
}

func validateDestination(item *op.Item) error {
	if item == nil {
		return &provider.Error{Kind: provider.InvalidBinding}
	}
	if item.Category != op.ItemCategorySecureNote {
		return &provider.Error{Kind: provider.InvalidState}
	}
	return nil
}

func applyWrites(item *op.Item, writes []provider.Write) error {
	if writes[0].Reference.Blob() {
		item.Notes = writes[0].Value.Reveal()
		return nil
	}
	return updateFields(item, writes)
}

func updateFields(item *op.Item, writes []provider.Write) error {
	for _, write := range writes {
		section, field := splitKey(write.Reference.Key)
		sectionID, err := ensureSection(item, section)
		if err != nil {
			return err
		}
		matches := matchingFieldIndexes(item, sectionID, field)
		switch len(matches) {
		case 0:
			item.Fields = append(item.Fields, op.ItemField{ID: field, Title: field, SectionID: sectionID, FieldType: op.ItemFieldTypeConcealed, Value: write.Value.Reveal()})
		case 1:
			item.Fields[matches[0]].Value = write.Value.Reveal()
		default:
			return &provider.Error{Kind: provider.Ambiguous}
		}
	}
	return nil
}

func matchingFieldIndexes(item *op.Item, sectionID *string, field string) []int {
	matches := make([]int, 0, 1)
	for i, candidate := range item.Fields {
		if (candidate.ID == field || candidate.Title == field) && candidate.FieldType == op.ItemFieldTypeConcealed && sameSection(candidate.SectionID, sectionID) {
			matches = append(matches, i)
		}
	}
	return matches
}

func ensureSection(item *op.Item, title string) (*string, error) {
	if title == "" {
		return nil, nil
	}
	id, err := findSection(item, title)
	var typed *provider.Error
	if err == nil {
		return id, nil
	}
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidBinding {
		return nil, err
	}
	item.Sections = append(item.Sections, op.ItemSection{ID: sectionID(len(item.Sections)), Title: title})
	return &item.Sections[len(item.Sections)-1].ID, nil
}

func sectionID(index int) string { return fmt.Sprintf("uno-%d", index) }

func environments(writes []provider.Write) []string {
	result := make([]string, 0, len(writes))
	for _, write := range writes {
		result = append(result, write.Environment)
	}
	sort.Strings(result)
	return result
}

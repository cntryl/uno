package onepassword

import (
	"context"
	"errors"
	"fmt"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cntryl/uno/internal/core/provider"
)

const conflictRetries = 3

type versionConflict interface{ VersionConflict() bool }

func (a *Adapter) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if err := provider.ValidateWriteGroup(writes); err != nil {
		return provider.Receipt{}, err
	}
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}
	for _, write := range writes {
		if sourceOnly(write.Reference) {
			return provider.Receipt{}, &provider.Error{Kind: provider.InvalidBinding}
		}
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
			return provider.Receipt{Completed: provider.Environments(writes)}, nil
		} else {
			var conflict versionConflict
			if !errors.As(err, &conflict) || !conflict.VersionConflict() {
				return provider.Receipt{}, remote(err)
			}
			if attempt == conflictRetries {
				return provider.Receipt{}, remote(err)
			}
			if err := a.waitBeforeRetry(ctx, attempt); err != nil {
				return provider.Receipt{}, err
			}
		}
	}
	return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
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
			if item.Fields[matches[0]].FieldType != op.ItemFieldTypeConcealed {
				return &provider.Error{Kind: provider.Ambiguous}
			}
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
		if candidate.FieldType == op.ItemFieldTypeConcealed && (candidate.ID == field || candidate.Title == field) && sameSection(candidate.SectionID, sectionID) {
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
	item.Sections = append(item.Sections, op.ItemSection{ID: nextSectionID(item), Title: title})
	return &item.Sections[len(item.Sections)-1].ID, nil
}

func nextSectionID(item *op.Item) string {
	used := make(map[string]bool, len(item.Sections))
	for _, section := range item.Sections {
		used[section.ID] = true
	}
	for index := 0; ; index++ {
		candidate := fmt.Sprintf("uno-%d", index)
		if !used[candidate] {
			return candidate
		}
	}
}

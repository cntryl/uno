package aws

import (
	"context"
	"sort"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type SSMAPI interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(context.Context, *ssm.PutParameterInput, ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

type SSM struct{ C SSMAPI }

func (s *SSM) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
	values := make(map[string]secret.Value, len(refs))
	for _, ref := range refs {
		value, err := s.read(ctx, ref)
		if err != nil {
			secret.DestroyMap(values)
			return nil, err
		}
		values[ref.Binding()] = value
	}
	return values, nil
}

func (s *SSM) read(ctx context.Context, ref provider.Reference) (secret.Value, error) {
	decrypt := true
	out, err := s.C.GetParameter(ctx, &ssm.GetParameterInput{Name: &ref.Container, WithDecryption: &decrypt})
	if err != nil {
		return secret.Value{}, remoteError(err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil || out.Parameter.Type != ssmtypes.ParameterTypeSecureString {
		return secret.Value{}, &provider.Error{Kind: provider.InvalidState}
	}
	return secret.New(*out.Parameter.Value), nil
}

func (s *SSM) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	provider.SortedWrites(writes)
	completed := make([]string, 0, len(writes))
	for _, write := range writes {
		if err := s.write(ctx, write); err != nil {
			return provider.Receipt{Completed: completed}, err
		}
		completed = append(completed, write.Environment)
	}
	return provider.Receipt{Completed: completed}, nil
}

func (s *SSM) write(ctx context.Context, write provider.Write) error {
	value := write.Value.Reveal()
	name := write.Reference.Container
	overwrite := true
	_, err := s.C.PutParameter(ctx, &ssm.PutParameterInput{
		Name: &name, Value: &value, Type: ssmtypes.ParameterTypeSecureString, Overwrite: &overwrite,
	})
	if err != nil {
		return remoteError(err)
	}
	return nil
}

func environments(writes []provider.Write) []string {
	result := make([]string, 0, len(writes))
	for _, write := range writes {
		result = append(result, write.Environment)
	}
	sort.Strings(result)
	return result
}

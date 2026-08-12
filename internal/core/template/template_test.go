package template

import (
	"strings"
	"testing"
)

func TestArrowMappingsInterpolationAndComments(t *testing.T) {
	env := map[string]string{"VAULT": "Production", "REGION": "us-east-1"}
	f, err := ParseEnv("# comment\nMY_API_KEY=op://$VAULT/item/MY_API_KEY -> aws-secrets-manager://${REGION}/item/MY_API_KEY\n", func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil || len(f.Entries) != 1 {
		t.Fatalf("file=%#v err=%v", f, err)
	}
	if f.Entries[0].Source != "op://Production/item/MY_API_KEY" || f.Entries[0].Destination != "aws-secrets-manager://us-east-1/item/MY_API_KEY" {
		t.Fatalf("entry=%#v", f.Entries[0])
	}
}
func TestInterpolationIsSinglePass(t *testing.T) {
	f, err := ParseEnv("K=op://$V/item/key -> aws-ssm://r/path\n", func(k string) (string, bool) { return "$SECOND", true })
	if err != nil || f.Entries[0].Source != "op://$SECOND/item/key" {
		t.Fatalf("file=%#v err=%v", f, err)
	}
}
func TestSafeFailures(t *testing.T) {
	cases := []string{"", "# comment only", "K=op://$MISSING/i/f -> aws-ssm://r/p", "K=x", "K=x -> y -> z", "K=x -> y\nK=a -> b", "K=x\x00 -> y"}
	for _, input := range cases {
		if _, err := ParseEnv(input, func(string) (string, bool) { return "", false }); err == nil {
			t.Fatalf("expected failure for %q", input)
		}
	}
}
func TestErrorsNeverContainEnvironmentValues(t *testing.T) {
	secret := "super-secret-value"
	_, err := ParseEnv("K=op://$V/item/key -> aws-ssm://r/$BAD\n", func(k string) (string, bool) {
		if k == "V" {
			return secret, true
		}
		return "", false
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error: %v", err)
	}
}

package template

import (
	"strings"
	"testing"

	"github.com/cntryl/uno/internal/aws"
	"github.com/cntryl/uno/internal/azure"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/gcp"
	"github.com/cntryl/uno/internal/onepassword"
	"github.com/cntryl/uno/internal/vault"
)

func TestShouldInterpolateVariablesAndSkipCommentsGivenArrowMappingFile(t *testing.T) {
	env := map[string]string{"VAULT": "Production", "REGION": "us-east-1"}
	f, err := ParseEnv("# comment\nMY_API_KEY=op://$VAULT/item/MY_API_KEY -> aws-secrets-manager://${REGION}/item/MY_API_KEY\n", func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil || len(f.Entries) != 1 {
		t.Fatalf("file=%#v err=%v", f, err)
	}
	if f.Entries[0].Source != "op://Production/item/MY_API_KEY" || f.Entries[0].Destination != "aws-secrets-manager://us-east-1/item/MY_API_KEY" {
		t.Fatalf("entry=%#v", f.Entries[0])
	}
}
func TestShouldNotReinterpolateGivenInterpolatedValueContainsVariableSyntax(t *testing.T) {
	f, err := ParseEnv("K=op://$V/item/key -> aws-ssm://r/path\n", func(k string) (string, bool) { return "$SECOND", true })
	if err != nil || f.Entries[0].Source != "op://$SECOND/item/key" {
		t.Fatalf("file=%#v err=%v", f, err)
	}
}
func TestShouldExpandAliasPlaceholdersOnceGivenExpandedValueContainsVariableSyntax(t *testing.T) {
	file, err := ParseEnv("@poop=fake://$FIRST\nKEY=fake://source -> @poop\n", func(key string) (string, bool) {
		if key == "FIRST" {
			return "$SECOND", true
		}
		return "must-not-be-used", true
	})
	if err != nil || file.Entries[0].Destination != "fake://$SECOND/KEY" {
		t.Fatalf("file=%#v err=%v", file, err)
	}
}
func TestShouldFailGivenMalformedOrIncompleteInput(t *testing.T) {
	cases := []string{"K=op://$MISSING/i/f -> aws-ssm://r/p", "K=x", "K=x -> y -> z", "K=x -> y\nK=a -> b", "K=x\x00 -> y"}
	for _, input := range cases {
		if _, err := ParseEnv(input, func(string) (string, bool) { return "", false }); err == nil {
			t.Fatalf("expected failure for %q", input)
		}
	}
}

func TestShouldAllowTemplateWithNoMappings(t *testing.T) {
	for _, input := range []string{"", "\n", "# no secrets are mapped yet\n\n"} {
		file, err := ParseEnv(input, func(string) (string, bool) { return "", false })
		if err != nil || file == nil || len(file.Entries) != 0 {
			t.Fatalf("input=%q file=%#v err=%v", input, file, err)
		}
	}
}
func TestShouldNotLeakEnvironmentValueInErrorGivenInterpolationFailure(t *testing.T) {
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

func TestShouldExpandNamedDestinationAliasesGivenSequentialDeclarations(t *testing.T) {
	env := map[string]string{"REGION": "us-east-1", "VAULT": "Production"}
	input := strings.Join([]string{
		"@runtime=aws-secrets-manager://$REGION/my-service/runtime",
		"MY_API_KEY=op://$VAULT/my-service/api_key -> @runtime",
		"MY_OTHER_KEY=op://$VAULT/my-service/other_key -> @runtime",
		"EXPLICIT=op://$VAULT/my-service/explicit -> aws-ssm://$REGION/my-service/renamed",
	}, "\n")
	file, err := ParseEnv(input, func(key string) (string, bool) { value, ok := env[key]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"aws-secrets-manager://us-east-1/my-service/runtime/MY_API_KEY",
		"aws-secrets-manager://us-east-1/my-service/runtime/MY_OTHER_KEY",
		"aws-ssm://us-east-1/my-service/renamed",
	}
	if len(file.Entries) != len(want) {
		t.Fatalf("entries=%#v", file.Entries)
	}
	for i := range want {
		if file.Entries[i].Destination != want[i] {
			t.Fatalf("entry %d destination=%q want=%q", i, file.Entries[i].Destination, want[i])
		}
	}
}

func TestShouldRejectInvalidNamedDestinationAliases(t *testing.T) {
	cases := map[string]string{
		"duplicate":            "@runtime=fake://target\n@runtime=fake://other\nK=fake://source -> @runtime",
		"undefined":            "K=fake://source -> @missing",
		"forward referenced":   "K=fake://source -> @runtime\n@runtime=fake://target",
		"malformed digit":      "@1runtime=fake://target\nK=fake://source -> fake://target",
		"malformed hyphen":     "@run-time=fake://target\nK=fake://source -> fake://target",
		"empty prefix":         "@runtime=\nK=fake://source -> @runtime",
		"trailing slash":       "@runtime=fake://target/\nK=fake://source -> @runtime",
		"chained":              "@first=@second\nK=fake://source -> @first",
		"interpolated chained": "@first=$PREFIX\nK=fake://source -> @first",
		"unused":               "@runtime=fake://target\nK=fake://source -> fake://other",
		"partial destination":  "@runtime=fake://target\nK=fake://source -> @runtime/OTHER_KEY",
		"alias source":         "@runtime=fake://target\nK=@runtime -> fake://other",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnv(input, func(key string) (string, bool) {
				if key == "PREFIX" {
					return "@second", true
				}
				return "value", true
			}); err == nil {
				t.Fatalf("expected failure for %q", input)
			}
		})
	}
}

func TestShouldBindAliasExpansionThroughEveryRegisteredDestinationProvider(t *testing.T) {
	registry := provider.NewRegistry()
	registry.Register("aws-secrets-manager", aws.Factory{})
	registry.Register("aws-secrets-manager-arn", aws.Factory{})
	registry.Register("aws-ssm", aws.Factory{})
	registry.Register("azure-key-vault", azure.Factory{})
	registry.Register("gcp-secret-manager", gcp.Factory{})
	registry.Register("vault", vault.Factory{})
	registry.Register("op", onepassword.Factory{})
	cases := map[string]string{
		"AWS name":  "aws-secrets-manager://us-east-1/my-service/runtime",
		"AWS ARN":   "aws-secrets-manager-arn://arn:aws:secretsmanager:us-east-1:123456789012:secret:runtime-AbCd12",
		"SSM":       "aws-ssm://us-east-1/my-service/runtime",
		"Azure":     "azure-key-vault://myvault.vault.azure.net/runtime",
		"GCP":       "gcp-secret-manager://my-project/runtime",
		"Vault":     "vault://secret/my-service/runtime",
		"1Password": "op://MyVault/runtime",
	}
	for name, prefix := range cases {
		t.Run(name, func(t *testing.T) {
			file, err := ParseEnv("@destination="+prefix+"\nMY_API_KEY=fake://source -> @destination", func(string) (string, bool) { return "", false })
			if err != nil {
				t.Fatal(err)
			}
			ref, err := registry.Parse(file.Entries[0].Destination)
			if err != nil {
				t.Fatal(err)
			}
			if name == "SSM" {
				if ref.Container != "/my-service/runtime/MY_API_KEY" || ref.Key != "" {
					t.Fatalf("reference=%#v", ref)
				}
			} else if ref.Key != "MY_API_KEY" {
				t.Fatalf("reference=%#v", ref)
			}
		})
	}
}

func TestShouldNotLeakExpandedAliasPrefixInErrors(t *testing.T) {
	secret := "private-destination-name"
	for _, input := range []string{
		"@runtime=fake://$PRIVATE/\nK=fake://source -> @runtime",
		"@runtime=fake://$PRIVATE\nK=fake://source -> @runtime\n@unused=fake://other",
	} {
		_, err := ParseEnv(input, func(string) (string, bool) { return secret, true })
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "fake://") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
}

func FuzzParseEnv(f *testing.F) {
	for _, seed := range []string{
		"MY_API_KEY=op://$VAULT/item/MY_API_KEY -> aws-secrets-manager://${REGION}/item/MY_API_KEY\n",
		"# comment\r\nKEY=source -> destination\r\n",
		"KEY=$ -> destination",
		"KEY=${UNCLOSED -> destination",
		"KEY=source -> destination -> extra",
		"KEY=source\x00 -> destination",
		"@runtime=aws-secrets-manager://$REGION/service/runtime\nKEY=source -> @runtime",
		"@runtime=destination/\nKEY=source -> @runtime",
		"KEY=source -> @undefined",
	} {
		f.Add(seed)
	}
	env := map[string]string{
		"VAULT":  "Production",
		"REGION": "us-east-1",
	}
	f.Fuzz(func(t *testing.T, input string) {
		file, err := ParseEnv(input, func(key string) (string, bool) {
			value, ok := env[key]
			return value, ok
		})
		if err == nil && file == nil {
			t.Fatal("successful parse returned nil file")
		}
		if err != nil && (strings.Contains(err.Error(), env["VAULT"]) || strings.Contains(err.Error(), env["REGION"])) {
			t.Fatalf("unsafe error: %v", err)
		}
	})
}

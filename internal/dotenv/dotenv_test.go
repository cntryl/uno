package dotenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cntryl/uno/internal/core/secret"
)

func TestShouldWriteSortedEscapedOwnerOnlyFileGivenUnsortedValuesWithSpecialCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.secrets")
	values := map[string]secret.Value{
		"SECOND": secret.New("line one\n\"$VALUE\"\\end`cmd`"),
		"FIRST":  secret.New("one"),
	}
	if err := Write(path, values); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // The path is inside t.TempDir and controlled by this test.
	if err != nil {
		t.Fatal(err)
	}
	// $ and ` are left untouched: standard dotenv parsers (e.g. the npm
	// `dotenv` package) don't treat "\$"/"\`" as escape sequences — they'd
	// keep the literal backslash, corrupting the secret value for consumers.
	want := "FIRST=\"one\"\nSECOND=\"line one\\n\\\"$VALUE\\\"\\\\end`cmd`\"\n"
	if string(data) != want {
		t.Fatalf("contents=%q want=%q", data, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestShouldReplaceExistingFileContentsGivenFileAlreadyExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.secrets")
	if err := os.WriteFile(path, []byte("OLD=\"value\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, map[string]secret.Value{"NEW": secret.New("value")}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // The path is inside t.TempDir and controlled by this test.
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "NEW=\"value\"\n" {
		t.Fatalf("contents=%q", data)
	}
}

func TestShouldReturnErrorWithoutLeakingValueGivenNULByte(t *testing.T) {
	value := "secret\x00value"
	if _, err := encode(value); err == nil || strings.Contains(err.Error(), value) {
		t.Fatalf("unsafe error: %v", err)
	}
}

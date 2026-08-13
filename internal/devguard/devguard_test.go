package devguard

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestShouldFailGivenLaterGitignoreRuleUnprotectsSecretPattern(t *testing.T) {
	directory := t.TempDir()
	initGit(t, directory)
	write(t, directory, ".gitignore", ".env.secrets*\n")
	if err := Check(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	write(t, directory, ".gitignore", ".env.secrets\n!.env.*\n")
	if err := Check(context.Background(), directory); err == nil {
		t.Fatal("expected later rule to invalidate protection")
	}
}

func TestShouldFailGivenDockerfileMissingMatchingDockerignoreEntry(t *testing.T) {
	directory := t.TempDir()
	initGit(t, directory)
	write(t, directory, ".gitignore", ".env.secrets*\n")
	if err := Check(context.Background(), directory); err != nil {
		t.Fatalf("without Dockerfile: %v", err)
	}
	write(t, directory, "Dockerfile.dev", "FROM scratch\n")
	if err := Check(context.Background(), directory); err == nil {
		t.Fatal("expected .dockerignore requirement")
	}
	write(t, directory, ".dockerignore", "node_modules\n/.env.secrets*\n")
	if err := Check(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	write(t, directory, "Dockerfile.dev.dockerignore", "node_modules\n")
	if err := Check(context.Background(), directory); err == nil {
		t.Fatal("expected Dockerfile-specific ignore requirement")
	}
	write(t, directory, "Dockerfile.dev.dockerignore", "/.env.secrets*\n")
	if err := Check(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
}

func TestShouldFailGivenGitNotOnPath(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("PATH", "")

	err := Check(context.Background(), directory)
	if err == nil || err.Error() != "dev requires git on PATH" {
		t.Fatalf("err=%v", err)
	}
}

func initGit(t *testing.T, directory string) {
	t.Helper()
	// #nosec G204 -- the test owns directory and no shell is used.
	if out, err := exec.CommandContext(t.Context(), "git", "init", "-q", directory).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
}

func write(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

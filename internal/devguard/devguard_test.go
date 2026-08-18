package devguard

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	if err := Check(context.Background(), directory); err == nil || err.Error() != `dev safety check failed: Dockerfile.dev uses .dockerignore, but .dockerignore does not exist; create it with ".env.secrets*" as its final active rule` {
		t.Fatalf("err=%v", err)
	}
	write(t, directory, ".dockerignore", "node_modules\n/.env.secrets*\n")
	if err := Check(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	write(t, directory, "Dockerfile.dev.dockerignore", "node_modules\n")
	if err := Check(context.Background(), directory); err == nil || err.Error() != `dev safety check failed: Dockerfile.dev.dockerignore does not protect .env.secrets and .env.secrets-*; make ".env.secrets*" its final active rule` {
		t.Fatalf("err=%v", err)
	}
	write(t, directory, "Dockerfile.dev.dockerignore", "/.env.secrets*\n")
	if err := Check(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
}

func TestShouldNameGitIgnoreTargetThatIsNotProtected(t *testing.T) {
	directory := t.TempDir()
	initGit(t, directory)
	write(t, directory, ".gitignore", ".env.secrets\n")

	err := Check(context.Background(), directory)
	if err == nil || err.Error() != `dev safety check failed: Git does not effectively ignore .env.secrets-*; add ".env.secrets*" to .gitignore after any conflicting negation rules` {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldNameBaseGitIgnoreTargetThatIsNotProtected(t *testing.T) {
	directory := t.TempDir()
	initGit(t, directory)
	write(t, directory, ".gitignore", ".env.secrets-*\n")

	err := Check(context.Background(), directory)
	if err == nil || err.Error() != `dev safety check failed: Git does not effectively ignore .env.secrets; add ".env.secrets*" to .gitignore after any conflicting negation rules` {
		t.Fatalf("err=%v", err)
	}
}

func TestDockerErrorDoesNotExposeAbsoluteDevelopmentDirectory(t *testing.T) {
	directory := t.TempDir()
	initGit(t, directory)
	write(t, directory, ".gitignore", ".env.secrets*\n")
	write(t, directory, "Dockerfile", "FROM scratch\n")

	err := Check(context.Background(), directory)
	if err == nil || strings.Contains(err.Error(), directory) {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldNameUnreadableDockerIgnoreWithoutExposingAbsolutePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use Unix permission bits")
	}
	directory := t.TempDir()
	initGit(t, directory)
	write(t, directory, ".gitignore", ".env.secrets*\n")
	write(t, directory, "Dockerfile", "FROM scratch\n")
	write(t, directory, "Dockerfile.dockerignore", ".env.secrets*\n")
	path := filepath.Join(directory, "Dockerfile.dockerignore")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	err := Check(context.Background(), directory)

	if err == nil || err.Error() != "dev safety check failed: could not read Dockerfile.dockerignore" || strings.Contains(err.Error(), directory) {
		t.Fatalf("err=%v", err)
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

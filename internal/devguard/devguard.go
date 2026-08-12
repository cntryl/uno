// Package devguard validates repository safeguards before local secrets are written.
package devguard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const secretsFile = ".env.secrets"

// Check requires the secrets file to be the final active ignore rule. Git and
// Docker both use last-match-wins semantics, so this deliberately small policy
// cannot be undone by a later wildcard or negation rule.
func Check(ctx context.Context, directory string) error {
	info, err := os.Lstat(filepath.Join(directory, secretsFile))
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("dev refuses a symlink at .env.secrets")
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not inspect .env.secrets")
	}
	if !gitIgnored(ctx, directory, secretsFile) || !gitIgnored(ctx, directory, secretsFile+"-probe") {
		return fmt.Errorf("dev requires .env.secrets and .env.secrets-* to be effectively ignored by Git")
	}
	// #nosec G204 -- arguments are passed directly to Git without a shell.
	tracked := exec.CommandContext(ctx, "git", "-C", directory, "ls-files", "--error-unmatch", "--", secretsFile)
	if tracked.Run() == nil {
		return fmt.Errorf("dev refuses a tracked .env.secrets")
	}
	ignoreFiles, err := dockerIgnoreFiles(directory)
	if err != nil {
		return fmt.Errorf("could not inspect development directory")
	}
	for _, path := range ignoreFiles {
		if !finalRuleIgnores(path, secretsFile) || !finalRuleIgnores(path, secretsFile+"-probe") {
			return fmt.Errorf("dev requires every applicable Docker ignore file to protect .env.secrets and .env.secrets-*")
		}
	}
	return nil
}

func gitIgnored(ctx context.Context, directory, name string) bool {
	// #nosec G204 -- arguments are passed directly to Git without a shell.
	cmd := exec.CommandContext(ctx, "git", "-C", directory, "check-ignore", "-q", "--", name)
	return cmd.Run() == nil
}
func finalRuleIgnores(path, target string) bool {
	contents, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return false
	}
	last := ""
	for _, raw := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		last = line
	}
	return last == target || last == "/"+target || last == secretsFile+"*" || last == "/"+secretsFile+"*"
}

func dockerIgnoreFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	paths := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && (name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.")) {
			path := filepath.Join(directory, name+".dockerignore")
			if _, err := os.Stat(path); os.IsNotExist(err) {
				path = filepath.Join(directory, ".dockerignore")
			}
			if !seen[path] {
				seen[path] = true
				paths = append(paths, path)
			}
		}
	}
	return paths, nil
}

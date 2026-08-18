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
	git, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("dev requires git on PATH")
	}
	if err := inspectSecretsFile(directory); err != nil {
		return err
	}
	if !gitIgnored(ctx, git, directory, secretsFile) {
		return fmt.Errorf(`dev safety check failed: Git does not effectively ignore .env.secrets; add ".env.secrets*" to .gitignore after any conflicting negation rules`)
	}
	if !gitIgnored(ctx, git, directory, secretsFile+"-probe") {
		return fmt.Errorf(`dev safety check failed: Git does not effectively ignore .env.secrets-*; add ".env.secrets*" to .gitignore after any conflicting negation rules`)
	}
	// #nosec G204 -- arguments are passed directly to Git without a shell.
	tracked := exec.CommandContext(ctx, git, "-C", directory, "ls-files", "--error-unmatch", "--", secretsFile)
	if tracked.Run() == nil {
		return fmt.Errorf("dev refuses a tracked .env.secrets")
	}
	return checkDockerIgnores(directory)
}
func inspectSecretsFile(directory string) error {
	info, err := os.Lstat(filepath.Join(directory, secretsFile))
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("dev refuses a symlink at .env.secrets")
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not inspect .env.secrets")
	}
	return nil
}
func checkDockerIgnores(directory string) error {
	contexts, err := dockerIgnoreFiles(directory)
	if err != nil {
		return fmt.Errorf("could not inspect development directory")
	}
	for _, dockerContext := range contexts {
		if _, err := os.Stat(dockerContext.ignorePath); os.IsNotExist(err) {
			return fmt.Errorf(`dev safety check failed: %s uses %s, but %s does not exist; create it with ".env.secrets*" as its final active rule`, dockerContext.dockerfile, dockerContext.ignoreName, dockerContext.ignoreName)
		}
		last, err := finalActiveRule(dockerContext.ignorePath)
		if err != nil {
			return fmt.Errorf("dev safety check failed: could not read %s", dockerContext.ignoreName)
		}
		if !ruleIgnores(last, secretsFile) || !ruleIgnores(last, secretsFile+"-probe") {
			return fmt.Errorf(`dev safety check failed: %s does not protect .env.secrets and .env.secrets-*; make ".env.secrets*" its final active rule`, dockerContext.ignoreName)
		}
	}
	return nil
}

func gitIgnored(ctx context.Context, git, directory, name string) bool {
	// #nosec G204 -- arguments are passed directly to Git without a shell.
	cmd := exec.CommandContext(ctx, git, "-C", directory, "check-ignore", "-q", "--", name)
	return cmd.Run() == nil
}
func finalActiveRule(path string) (string, error) {
	contents, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	last := ""
	for _, raw := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		last = line
	}
	return last, nil
}

func ruleIgnores(rule, target string) bool {
	return rule == target || rule == "/"+target || rule == secretsFile+"*" || rule == "/"+secretsFile+"*"
}

type dockerContext struct {
	dockerfile string
	ignoreName string
	ignorePath string
}

func dockerIgnoreFiles(directory string) ([]dockerContext, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	contexts := []dockerContext{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && (name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.")) {
			ignoreName := name + ".dockerignore"
			path := filepath.Join(directory, ignoreName)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				ignoreName = ".dockerignore"
				path = filepath.Join(directory, ignoreName)
			}
			if !seen[path] {
				seen[path] = true
				contexts = append(contexts, dockerContext{dockerfile: name, ignoreName: ignoreName, ignorePath: path})
			}
		}
	}
	return contexts, nil
}

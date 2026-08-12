// Package dotenv atomically persists resolved development secrets.
package dotenv

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cntryl/uno/internal/core/secret"
)

// Write atomically replaces path with a deterministic, owner-only dotenv file.
func Write(path string, values map[string]secret.Value) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".env.secrets-*")
	if err != nil {
		return fmt.Errorf("could not create temporary secrets file")
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not secure temporary secrets file")
	}
	if err := secureFile(temporaryPath); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not secure temporary secrets file")
	}
	for _, key := range secret.SortedKeys(values) {
		encoded, encodeErr := encode(values[key].Reveal())
		if encodeErr != nil {
			_ = temporary.Close()
			return fmt.Errorf("could not encode secret %s", key)
		}
		if _, err := fmt.Fprintf(temporary, "%s=%s\n", key, encoded); err != nil {
			_ = temporary.Close()
			return fmt.Errorf("could not write temporary secrets file")
		}
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("could not sync temporary secrets file")
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("could not close temporary secrets file")
	}
	if err := replaceFile(temporaryPath, path); err != nil {
		return fmt.Errorf("could not replace secrets file")
	}
	if err := secureFile(path); err != nil {
		return fmt.Errorf("could not verify secrets file permissions")
	}
	return nil
}

func encode(value string) (string, error) {
	if strings.ContainsRune(value, 0) {
		return "", fmt.Errorf("value contains NUL")
	}
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t")
	return "\"" + replacer.Replace(value) + "\"", nil
}

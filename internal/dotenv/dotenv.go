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
	if err := writeTemporary(temporary, temporaryPath, values); err != nil {
		return err
	}
	if err := replaceFile(temporaryPath, path); err != nil {
		return fmt.Errorf("could not replace secrets file")
	}
	if err := secureFile(path); err != nil {
		return fmt.Errorf("could not verify secrets file permissions")
	}
	return nil
}
func writeTemporary(file *os.File, path string, values map[string]secret.Value) error {
	if err := file.Chmod(0o600); err != nil {
		return closeWith(file, "could not secure temporary secrets file")
	}
	if err := secureFile(path); err != nil {
		return closeWith(file, "could not secure temporary secrets file")
	}
	for _, key := range secret.SortedKeys(values) {
		encoded, err := encode(values[key].Reveal())
		if err != nil {
			return closeWith(file, "could not encode secret "+key)
		}
		if _, err := fmt.Fprintf(file, "%s=%s\n", key, encoded); err != nil {
			return closeWith(file, "could not write temporary secrets file")
		}
	}
	if err := file.Sync(); err != nil {
		return closeWith(file, "could not sync temporary secrets file")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("could not close temporary secrets file")
	}
	return nil
}
func closeWith(file *os.File, message string) error {
	_ = file.Close()
	return fmt.Errorf("%s", message)
}

func encode(value string) (string, error) {
	if strings.ContainsRune(value, 0) {
		return "", fmt.Errorf("value contains NUL")
	}
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t")
	return "\"" + replacer.Replace(value) + "\"", nil
}

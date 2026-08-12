//go:build !windows

package dotenv

import "os"

func secureFile(string) error { return nil }

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}

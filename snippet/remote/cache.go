package remote

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

func getOrCreateCacheFile(serviceId string, version int64) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", errors.WithStack(err)
	}

	// Ensure cache directory exists
	falcoCacheDir := filepath.Join(dir, "falco")
	if _, err := os.Stat(falcoCacheDir); err != nil {
		if err := os.Mkdir(falcoCacheDir, 0o755); err != nil {
			return "", errors.WithStack(err)
		}
	}

	return filepath.Join(
		falcoCacheDir,
		fmt.Sprintf("%s-%d.json", serviceId, version),
	), nil
}

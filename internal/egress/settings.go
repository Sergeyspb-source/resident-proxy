package egress

import (
	"errors"
	"os"
	"path/filepath"
)

// GPT: Missing settings from older installations select the normal system route.
func Load(path string) (string, error) {
	if path == "" {
		return System, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return System, nil
	}
	if err != nil {
		return "", err
	}
	return readMode(string(data))
}

// GPT: Validate and persist the mode before changing any live traffic policy.
func Save(path, mode string) error {
	if !validMode(mode) || (mode == Direct && !Supported()) {
		return errors.New("egress mode is unavailable")
	}
	if path == "" {
		return errors.New("egress settings storage is unavailable")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".egress-mode-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := tmp.WriteString(mode + "\n"); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

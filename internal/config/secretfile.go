package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
)

const maxSecretFileBytes = 64 << 10

var ErrInvalidSecretFile = errors.New("INVALID_SECRET_FILE")

// ReadSecretFile reads a bounded, owner-only regular file. The returned bytes
// are intended for transient in-process use and must never be logged or stored
// in control-plane metadata.
func ReadSecretFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, ErrInvalidSecretFile
	}
	linkInfo, err := os.Lstat(path)
	if err != nil || linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() || linkInfo.Mode().Perm()&0o077 != 0 || linkInfo.Size() > maxSecretFileBytes {
		return nil, ErrInvalidSecretFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidSecretFile
	}
	defer func() {
		_ = file.Close()
	}()
	fileInfo, err := file.Stat()
	if err != nil || !os.SameFile(linkInfo, fileInfo) || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalidSecretFile
	}
	value, err := io.ReadAll(io.LimitReader(file, maxSecretFileBytes+1))
	if err != nil || len(value) == 0 || len(value) > maxSecretFileBytes {
		clear(value)
		return nil, ErrInvalidSecretFile
	}
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 {
		clear(value)
		return nil, ErrInvalidSecretFile
	}
	secret := bytes.Clone(value)
	clear(value)
	return secret, nil
}

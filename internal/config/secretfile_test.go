package config

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecretFileRequiresOwnerOnlyRegularFile(t *testing.T) {
	t.Parallel()

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	loaded, err := ReadSecretFile(path)
	if err != nil {
		t.Fatalf("ReadSecretFile() error = %v", err)
	}
	if !bytes.Equal(loaded, secret) {
		t.Fatal("ReadSecretFile() returned different bytes")
	}
	clear(secret)
	clear(loaded)
}

func TestReadSecretFileRejectsBroadPermissionsAndSymlinks(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "credential")
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	clear(value)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := ReadSecretFile(path); err == nil {
		t.Fatal("ReadSecretFile() accepted group/world-readable file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	linkPath := filepath.Join(directory, "credential-link")
	if err := os.Symlink(path, linkPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := ReadSecretFile(linkPath); err == nil {
		t.Fatal("ReadSecretFile() accepted a symlink")
	}
}

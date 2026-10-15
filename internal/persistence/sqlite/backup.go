package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrInvalidBackupPath = errors.New("INVALID_BACKUP_PATH")
	ErrInsecureBackupDir = errors.New("INSECURE_BACKUP_DIRECTORY")
	ErrBackupExists      = errors.New("BACKUP_ALREADY_EXISTS")
)

// Backup writes a consistent, standalone SQLite snapshot. The destination must
// be new and inside a directory inaccessible to other users.
func (store *Store) Backup(ctx context.Context, destination string) error {
	if store == nil || store.db == nil || destination == "" || strings.TrimSpace(destination) != destination {
		return ErrInvalidBackupPath
	}
	absDestination, err := filepath.Abs(destination)
	if err != nil || absDestination == store.path {
		return ErrInvalidBackupPath
	}
	directory := filepath.Dir(absDestination)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("unable to prepare backup directory")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ErrInsecureBackupDir
	}
	if _, err := os.Lstat(absDestination); err == nil {
		return ErrBackupExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrInvalidBackupPath
	}

	temporary, err := os.CreateTemp(directory, ".srp-backup-*")
	if err != nil {
		return errors.New("unable to reserve backup path")
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("unable to prepare backup file")
	}
	if err := os.Remove(temporaryPath); err != nil {
		return errors.New("unable to prepare backup file")
	}

	quotedPath := "'" + strings.ReplaceAll(temporaryPath, "'", "''") + "'"
	if _, err := store.db.ExecContext(ctx, "VACUUM INTO "+quotedPath); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("unable to create consistent SQLite backup")
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("unable to protect SQLite backup")
	}
	if err := os.Link(temporaryPath, absDestination); err != nil {
		_ = os.Remove(temporaryPath)
		if errors.Is(err, os.ErrExist) {
			return ErrBackupExists
		}
		return errors.New("unable to publish SQLite backup")
	}
	if err := os.Remove(temporaryPath); err != nil {
		_ = os.Remove(absDestination)
		return errors.New("unable to finalize SQLite backup")
	}
	return nil
}

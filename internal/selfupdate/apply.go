package selfupdate

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	minio "github.com/minio/selfupdate"
)

// applyBinary replaces the currently running executable with newBinary.
// The atomic replace, fsync, Windows rename dance and rollback are owned by
// github.com/minio/selfupdate.
func applyBinary(newBinary []byte) error {
	return applyBinaryTo(newBinary, "")
}

// applyBinaryTo replaces the binary at targetPath. An empty targetPath means
// the running executable.
func applyBinaryTo(newBinary []byte, targetPath string) error {
	sum := sha256.Sum256(newBinary)
	return applyWithOptions(newBinary, minio.Options{
		TargetPath: targetPath,
		TargetMode: 0o755,
		Hash:       crypto.SHA256,
		Checksum:   sum[:],
	})
}

// applyWithOptions is the single seam onto minio/selfupdate, so tests can
// exercise failure and rollback paths.
func applyWithOptions(newBinary []byte, opts minio.Options) error {
	if err := minio.Apply(bytes.NewReader(newBinary), opts); err != nil {
		if rollbackErr := minio.RollbackError(err); rollbackErr != nil {
			return fmt.Errorf("update failed and rollback also failed, restore the binary manually: %w", errors.Join(err, rollbackErr))
		}
		return err
	}
	return nil
}

//go:build selfupdate_e2e

// Package selfupdate's end-to-end apply tests.
//
// The rest of apply_test.go replaces inert byte blobs. That proves the
// bookkeeping but never touches the property that actually differs per
// platform: on Windows a running executable cannot be deleted, only renamed,
// which is the whole reason minio/selfupdate swaps with two renames instead of
// writing over the target in place. These tests compile real binaries, execute
// them, and replace them through grant's own apply path while a process is
// still running from the image - so the Windows file-locking semantics are
// genuinely in play.
//
// Build-tagged because they invoke the Go toolchain and take seconds. Run with:
//
//	go test -tags=selfupdate_e2e ./internal/selfupdate/
//
// No network access is required: the fixture is a self-contained module with no
// dependencies, so nothing is downloaded from GitHub.

package selfupdate

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	minio "github.com/minio/selfupdate"
)

const (
	variantA = "VARIANT-A"
	variantB = "VARIANT-B"
)

// fixtureMain is a stand-in for grant: it prints the version baked in at link
// time, and with the "hold" argument stays alive until its stdin is closed. The
// held mode is what keeps the executable image mapped, and therefore locked on
// Windows, while the swap happens.
const fixtureMain = `package main

import (
	"bufio"
	"fmt"
	"os"
)

var version = "unset"

func main() {
	fmt.Println(version)
	if len(os.Args) > 1 && os.Args[1] == "hold" {
		// Block until the test closes our stdin. Reading to EOF is enough.
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
`

const fixtureMod = "module grantfixture\n\ngo 1.25\n"

// exeSuffix matches what the real release artifacts use.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// goTool locates the toolchain used to build the fixtures.
func goTool(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain not on PATH: %v", err)
	}
	return path
}

// buildVariants compiles the fixture twice - once per version string - and
// returns the two binaries as bytes, ready to be written to a target path or
// handed to applyBinaryTo.
func buildVariants(t *testing.T) (a, b []byte) {
	t.Helper()

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(fixtureMain), 0o600); err != nil {
		t.Fatalf("write fixture main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte(fixtureMod), 0o600); err != nil {
		t.Fatalf("write fixture go.mod: %v", err)
	}

	build := func(version string) []byte {
		out := filepath.Join(t.TempDir(), "fixture"+exeSuffix())
		cmd := exec.CommandContext(t.Context(), goTool(t),
			"build", "-o", out, "-ldflags", "-X main.version="+version, ".")
		cmd.Dir = src
		// GOFLAGS is cleared so a -mod setting from the parent module cannot
		// leak in; GOTOOLCHAIN=local keeps the build off the network.
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOTOOLCHAIN=local")
		if combined, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build fixture %s: %v\n%s", version, err, combined)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read built fixture %s: %v", version, err)
		}
		return data
	}

	return build(variantA), build(variantB)
}

// installBinary writes contents to a fresh directory as an executable target,
// mirroring an installed grant.
func installBinary(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grant"+exeSuffix())
	if err := os.WriteFile(path, contents, 0o755); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("install fixture binary: %v", err)
	}
	return path
}

// runBinary executes the target and returns the version it printed.
func runBinary(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), path).Output()
	if err != nil {
		t.Fatalf("run %s: %v (output %q)", path, err, out)
	}
	return strings.TrimSpace(string(out))
}

// heldProcess is a live process running from the target image.
type heldProcess struct {
	version string
	exited  chan struct{}
	release func()
}

// alive reports whether the process is still running. Without this the "held"
// cases could silently degrade into the idle cases and the test would claim a
// coverage it does not have.
func (h *heldProcess) alive() bool {
	select {
	case <-h.exited:
		return false
	default:
		return true
	}
}

// holdBinary starts the target in "hold" mode and waits until it has printed
// its version, which proves the image is mapped and the process is live. The
// returned release function shuts it down and waits for it to exit.
//
// On Windows this is what makes the test meaningful: while this process runs,
// the target file cannot be deleted, only renamed - which is exactly the
// constraint the two-rename swap exists to satisfy.
func holdBinary(t *testing.T, path string) *heldProcess {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), path, "hold")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start held binary: %v", err)
	}

	line, readErr := bufio.NewReader(stdout).ReadString('\n')

	exited := make(chan struct{})
	waited := make(chan struct{})
	go func() {
		defer close(waited)
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		close(exited)
	}()

	released := false
	h := &heldProcess{version: strings.TrimSpace(line), exited: exited}
	h.release = func() {
		if released {
			return
		}
		released = true
		_ = stdin.Close()
		<-waited
	}
	t.Cleanup(h.release)

	if readErr != nil {
		h.release()
		t.Fatalf("held binary produced no output: %v", readErr)
	}
	return h
}

// assertNoStagedFile pins that the staged replacement never survives, on any
// platform and in any outcome.
func assertNoStagedFile(t *testing.T, target string) {
	t.Helper()
	if _, err := os.Stat(stagedPath(target)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staged %s survived the apply (stat err %v)", stagedPath(target), err)
	}
}

// TestSelfUpdateE2EReplacesBinary replaces a binary that has just been executed
// with a different build of itself, and proves the replacement is the thing
// that runs afterwards. The "running during the swap" case is the Windows
// locked-file path.
func TestSelfUpdateE2EReplacesBinary(t *testing.T) {
	oldBin, newBin := buildVariants(t)

	tests := []struct {
		name string
		// hold keeps a process running from the target image across the swap.
		hold bool
	}{
		{name: "target idle during the swap", hold: false},
		{name: "target running during the swap", hold: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := installBinary(t, oldBin)

			// 1. The installed binary is variant A.
			if got := runBinary(t, target); got != variantA {
				t.Fatalf("before update: %q, want %q", got, variantA)
			}

			var held *heldProcess
			if tt.hold {
				held = holdBinary(t, target)
				if held.version != variantA {
					t.Fatalf("held process reported %q, want %q", held.version, variantA)
				}
			}

			// 2. Replace it through grant's own apply path.
			if held != nil && !held.alive() {
				t.Fatal("held process exited before the swap: the locked-file path was not exercised")
			}
			if err := applyBinaryTo(newBin, target); err != nil {
				t.Fatalf("applyBinaryTo while hold=%v: %v", tt.hold, err)
			}
			if held != nil {
				if !held.alive() {
					t.Error("held process exited during the swap: the locked-file path was not exercised")
				}
				held.release()
			}

			// 3. The new binary is what runs now.
			if got := runBinary(t, target); got != variantB {
				t.Errorf("after update: %q, want %q", got, variantB)
			}

			assertNoStagedFile(t, target)

			backup := oldPathFor(target)
			_, backupErr := os.Stat(backup)
			switch {
			case runtime.GOOS == "windows" && tt.hold:
				// Documented Windows behavior, not a test allowance: minio
				// cannot os.Remove the backup while a process is still running
				// from that image, so it marks it hidden and leaves it. What
				// must hold is that it does not accumulate - the next update
				// clears it (CommitBinary removes the old path first).
				if backupErr != nil {
					t.Logf("note: %s was removed even with the image held", backup)
				}
				if err := applyBinaryTo(oldBin, target); err != nil {
					t.Fatalf("second applyBinaryTo: %v", err)
				}
				if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s survived an update performed with nothing running (stat err %v)", backup, err)
				}
				if got := runBinary(t, target); got != variantA {
					t.Errorf("after the second update: %q, want %q", got, variantA)
				}
				assertNoStagedFile(t, target)
			default:
				if !errors.Is(backupErr, os.ErrNotExist) {
					t.Errorf("%s survived the apply (stat err %v)", backup, backupErr)
				}
			}
		})
	}
}

// TestSelfUpdateE2ERollsBackRunningBinary drives the real failure path with a
// real executable: the first rename has already moved the running binary aside
// when the second rename fails, so minio must rename it back - and the restored
// file must still be an executable that runs.
func TestSelfUpdateE2ERollsBackRunningBinary(t *testing.T) {
	oldBin, newBin := buildVariants(t)

	tests := []struct {
		name string
		hold bool
	}{
		{name: "target idle during the failed swap", hold: false},
		{name: "target running during the failed swap", hold: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := installBinary(t, oldBin)

			var held *heldProcess
			if tt.hold {
				held = holdBinary(t, target)
			}

			// Let staging and the first rename succeed, then remove the staged
			// file so the second rename fails and rollback has to run.
			origCommit := commitFn
			defer func() { commitFn = origCommit }()
			commitFn = func(opts minio.Options) error {
				if err := os.Remove(stagedPath(target)); err != nil {
					t.Errorf("remove staged file: %v", err)
				}
				return origCommit(opts)
			}

			if held != nil && !held.alive() {
				t.Fatal("held process exited before the swap: the locked-file path was not exercised")
			}
			err := applyWithOptions(bytes.NewReader(newBin), minio.Options{
				TargetPath: target,
				TargetMode: 0o755,
			})
			if err == nil {
				t.Fatal("expected the commit to fail, got nil")
			}
			if rbErr := minio.RollbackError(err); rbErr != nil {
				t.Fatalf("rollback failed, the binary is gone: %v", rbErr)
			}
			if strings.Contains(err.Error(), "no longer exists") {
				t.Errorf("error wrongly reports an unrecoverable state: %v", err)
			}

			if held != nil {
				if !held.alive() {
					t.Error("held process exited during the swap: the locked-file path was not exercised")
				}
				held.release()
			}

			// The restored binary must still be a working executable, not just
			// a file with the right bytes.
			if got := runBinary(t, target); got != variantA {
				t.Errorf("after rollback: %q, want %q", got, variantA)
			}

			assertNoStagedFile(t, target)
			if _, statErr := os.Stat(oldPathFor(target)); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("%s survived the rollback (stat err %v)", oldPathFor(target), statErr)
			}
		})
	}
}

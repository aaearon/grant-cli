package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestExecCredentialGuardsProcessStdout is the test the older one should have
// been. TestExecCredentialStdoutIsOnlyJSON reproduces one specific SDK branch —
// the browser-redirect message — and so proved only that that branch behaves.
// The Survey prompts the SDK drives for PIN entry, MFA-method selection, OOB
// verification and username/password default their Stdio.Out to os.Stdout and
// consult nothing at all, and they walked straight past it.
//
// This test asserts the property rather than a branch: an arbitrary write to
// os.Stdout from inside the credential flow does not reach the process's real
// standard output, and what does reach it is exactly the ExecCredential JSON.
// The command runs without cmd.SetOut, so the JSON travels the production route
// through the guard's saved descriptor instead of a test buffer.
func TestExecCredentialGuardsProcessStdout(t *testing.T) {
	realStdout := os.Stdout
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pipeW
	t.Cleanup(func() { os.Stdout = realStdout })

	// Captured before the command runs, exactly as github.com/pkg/browser
	// captures os.Stdout into a package-level var at init. Only the descriptor
	// layer of the guard can contain a writer like this.
	preCaptured := os.Stdout
	fdLayer := stdoutFDReservationWorks(t)

	provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
	resolveDeps := func(bool) (*execCredentialDeps, error) {
		// Layer 1, asserted directly: anything resolving os.Stdout right now
		// gets stderr. On Windows this is the whole of the guarantee.
		if os.Stdout != os.Stderr {
			t.Errorf("os.Stdout was not redirected during the credential flow; got %v", os.Stdout)
		}

		// Plain writes, of no particular kind. They stand in for every SDK and
		// third-party writer, named or not, that resolves os.Stdout when it
		// runs: Survey's default Stdio.Out, log.New(os.Stdout, ...),
		// exec.Cmd.Stdout assignments, the browser-redirect message.
		fmt.Fprintln(os.Stdout, "Enter your PIN:")
		fmt.Fprint(os.Stdout, "Select an MFA method: ")

		if fdLayer {
			fmt.Fprintln(preCaptured, "subprocess chatter through a captured descriptor")
		}

		return &execCredentialDeps{provider: provider, elevateToken: "isp-jwt"}, nil
	}

	execCmd := NewK8sExecCredentialCommandWithDeps(resolveDeps, nil,
		execInfoJSON(t, "client.authentication.k8s.io/v1beta1", true))

	var errBuf bytes.Buffer
	execCmd.SetErr(&errBuf)
	execCmd.SetArgs([]string{"--csp", "aws", "--fqdn", "prod.eks.example"})
	if err := execCmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errBuf.String())
	}

	if err := pipeW.Close(); err != nil {
		t.Fatal(err)
	}
	onStdout, err := io.ReadAll(pipeR)
	if err != nil {
		t.Fatal(err)
	}

	trimmed := strings.TrimSpace(string(onStdout))
	var got map[string]any
	if err := json.Unmarshal([]byte(trimmed), &got); err != nil {
		t.Fatalf("the process stdout is not exactly one ExecCredential document (%v); "+
			"something inside the credential flow escaped the stdout guard:\n%q", err, string(onStdout))
	}
	if got["kind"] != "ExecCredential" {
		t.Errorf("kind = %v, want ExecCredential", got["kind"])
	}

	// The guard hands os.Stdout back to whatever it found, not to the real one.
	if os.Stdout != pipeW {
		t.Errorf("os.Stdout was not restored after the command; got %v", os.Stdout)
	}
}

// TestStdoutGuardRestoresOnPanic asserts the reservation is not leaked when the
// guarded code panics. A leaked guard would leave the whole process writing its
// standard output to stderr.
func TestStdoutGuardRestoresOnPanic(t *testing.T) {
	realStdout := os.Stdout
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipeR.Close() }()
	os.Stdout = pipeW
	t.Cleanup(func() { os.Stdout = realStdout })

	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected the panic to propagate")
			}
		}()
		guard := reserveStdout()
		defer guard.Release()
		panic("boom")
	}()

	if os.Stdout != pipeW {
		t.Fatalf("os.Stdout was not restored after a panic; got %v", os.Stdout)
	}

	// The descriptor is back as well: a write to os.Stdout reaches the pipe.
	const marker = "stdout is usable again\n"
	if _, err := fmt.Fprint(os.Stdout, marker); err != nil {
		t.Fatal(err)
	}
	if err := pipeW.Close(); err != nil {
		t.Fatal(err)
	}
	back, err := io.ReadAll(pipeR)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != marker {
		t.Errorf("after release, stdout carried %q, want %q", string(back), marker)
	}
}

// stdoutFDReservationWorks reports whether this platform can re-point the
// descriptor behind standard output, which is what decides whether writers that
// captured os.Stdout before the guard was installed are contained. False on
// Windows, where the guard's guarantee is the os.Stdout swap alone.
func stdoutFDReservationWorks(t *testing.T) bool {
	t.Helper()
	probeR, probeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = probeR.Close()
		_ = probeW.Close()
	}()
	_, restore, err := reserveStdoutFD(probeW, os.Stderr)
	if err != nil {
		return false
	}
	restore()
	return true
}

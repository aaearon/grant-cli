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

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
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

// TestExecCredentialGuardsCobraPreRun covers the gap the RunE-installed guard
// left open. Cobra runs PersistentPreRunE before RunE, so a guard taken inside
// RunE arrives too late for anything the root pre-run writes. That is not
// hypothetical: on --verbose the pre-run emits the WSL keyring notice through
// the package-level `log`, an SDK logger built on os.Stdout, straight into
// kubectl's protocol stream.
//
// This drives the production path — the real root command, the real
// PersistentPreRunE, the real keyring notice — through
// executeWithKeyringOverride, which is where Execute now installs the guard.
func TestExecCredentialGuardsCobraPreRun(t *testing.T) {
	resetKeyringOverrideState(t)
	restoreVerbose := verbose
	restoreArgValidation := passedArgValidation
	t.Cleanup(func() {
		verbose = restoreVerbose
		passedArgValidation = restoreArgValidation
	})

	realStdout := os.Stdout
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pipeW
	t.Cleanup(func() { os.Stdout = realStdout })

	// Built here, so it captures the pipe exactly as the production `log` var
	// captures the real stdout at init. Only the descriptor layer can contain a
	// writer like this.
	log = common.GetLogger("grant", -1)
	fdLayer := stdoutFDReservationWorks(t)

	// Make the pre-run actually emit the notice.
	keyringApply = func() (bool, string, error) { return true, "WSL detected: forcing the file-based keyring", nil }

	provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
	execCmd := NewK8sExecCredentialCommandWithDeps(depsFor(provider), nil,
		execInfoJSON(t, "client.authentication.k8s.io/v1beta1", true))

	k8sParent := newK8sParent()
	k8sParent.AddCommand(execCmd)
	root := newRootCommand(nil)
	root.AddCommand(k8sParent)

	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	args := []string{"--verbose", "k8s", "exec-credential", "--csp", "aws", "--fqdn", "prod.eks.example"}
	root.SetArgs(args)

	if err := executeWithKeyringOverride(root, args...); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errBuf.String())
	}
	if !verbose {
		t.Fatal("the root PersistentPreRunE did not run; this test is not exercising production wiring")
	}

	if err := pipeW.Close(); err != nil {
		t.Fatal(err)
	}
	onStdout, err := io.ReadAll(pipeR)
	if err != nil {
		t.Fatal(err)
	}

	if !fdLayer {
		// Windows: the descriptor layer is unavailable, so a logger that
		// captured os.Stdout at init still reaches the real stdout. Assert the
		// weaker property the platform can actually deliver, rather than
		// pretending parity.
		if !strings.Contains(string(onStdout), `"kind":"ExecCredential"`) {
			t.Fatalf("the ExecCredential never reached stdout:\n%q", string(onStdout))
		}
		return
	}

	trimmed := strings.TrimSpace(string(onStdout))
	var got map[string]any
	if err := json.Unmarshal([]byte(trimmed), &got); err != nil {
		t.Fatalf("the process stdout is not exactly one ExecCredential document (%v); "+
			"something written before RunE escaped the stdout guard:\n%q", err, string(onStdout))
	}
	if got["kind"] != "ExecCredential" {
		t.Errorf("kind = %v, want ExecCredential", got["kind"])
	}
}

// TestInstallProtocolStdoutGuardOnlyForProtocolCommands keeps the guard from
// hijacking stdout for ordinary commands, whose stdout is human output or JSON
// the user asked for.
func TestInstallProtocolStdoutGuardOnlyForProtocolCommands(t *testing.T) {
	provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
	execCmd := NewK8sExecCredentialCommandWithDeps(depsFor(provider), nil, "")
	k8sParent := newK8sParent()
	k8sParent.AddCommand(execCmd)
	root := newRootCommand(nil)
	root.AddCommand(k8sParent)

	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"exec-credential owns stdout", []string{"k8s", "exec-credential", "--csp", "aws"}, true},
		{"exec-credential behind flags", []string{"--verbose", "k8s", "exec-credential"}, true},
		{"k8s parent does not", []string{"k8s"}, false},
		{"root does not", nil, false},
		{"unknown command does not", []string{"nope"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := installProtocolStdoutGuard(root, tt.args)
			defer guard.Release()
			if got := guard != nil; got != tt.want {
				t.Errorf("installProtocolStdoutGuard(%v) reserved = %v, want %v", tt.args, got, tt.want)
			}
			if guard != nil && os.Stdout != os.Stderr {
				t.Error("the guard was installed but stdout was not redirected")
			}
		})
	}
	if activeStdoutGuard != nil {
		t.Error("a guard leaked past its Release")
	}
}

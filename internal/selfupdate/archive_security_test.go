package selfupdate

// SECURITY FIXTURES — defensive, not offensive.
//
// grant update downloads a release archive it did not build the moment it runs
// and unpacks it. This file exercises the guards that already exist in
// extractFromTarGz/extractFromZip/checkArchivePath against archives shaped the
// way a tampered release would be shaped: absolute paths, Windows
// drive-absolute and UNC paths, "..", empty names, non-regular entries and
// oversized entries.
//
// Every fixture here is built in memory and is only ever fed to the in-memory
// extractor. Nothing in this file writes to the filesystem, creates or follows
// a link, executes anything, or reaches the network — the payload bytes are
// inert ASCII. Every case asserts REJECTION: the test fails if grant accepts
// the archive. Their sole purpose is to make a regression in those guards fail
// the build.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io/fs"
	"strings"
	"testing"
)

// Hostile entry names, one per guard in checkArchivePath. The payload is inert
// text: nothing dereferences these names.
const (
	hostileTraversalName          = "../evil"
	hostileBackslashTraversalName = `..\evil`
	hostileAbsoluteName           = "/etc/passwd"
	hostileDriveName              = `C:\grant.exe`
	hostileDriveLowerName         = `c:\grant.exe`
	hostileDriveSlashName         = "C:/grant.exe"
	hostileUNCName                = "//host/share/grant"
	hostileBackslashUNCName       = `\\host\share\grant`
	hostileEmptyName              = ""
	hostileSymlinkTarget          = "/etc/passwd"
	hostilePayload                = "inert fixture payload, never written to disk"
)

// fixtureBinaryContents is the benign "grant binary" placed beside a hostile
// entry so that a rejection can never be attributed to the archive simply not
// containing a binary.
const fixtureBinaryContents = "\x7fELF fake grant binary"

// tarEntry describes one tar member, including the fields buildTarGz cannot
// express: a non-regular type flag, a link name, and a declared size that
// disagrees with the body.
type tarEntry struct {
	name     string
	body     string
	typeflag byte // zero value means tar.TypeReg
	linkname string
	size     int64 // zero means len(body)
}

// zipEntry describes one zip member. A name ending in "/" plus fs.ModeDir
// produces a directory entry.
type zipEntry struct {
	name string
	body string
	mode fs.FileMode
}

// buildTarGzEntries builds an in-memory tar.gz from fully specified entries.
func buildTarGzEntries(t testing.TB, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		size := e.size
		if size == 0 {
			size = int64(len(e.body))
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o755,
			Size:     size,
			Typeflag: typeflag,
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %q: %v", e.name, err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write tar body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// buildZipEntries builds an in-memory zip from fully specified entries.
func buildZipEntries(t testing.TB, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			hdr.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", e.name, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("write zip entry %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// buildHostileTarGz / buildHostileZip are buildTarGzEntries / buildZipEntries
// under a name that says what the call site is doing: assembling a
// deliberately malformed archive that the extractor must refuse. They exist so
// a reader of a test case does not have to infer intent from the entry names.
func buildHostileTarGz(t testing.TB, entries []tarEntry) []byte {
	t.Helper()
	return buildTarGzEntries(t, entries)
}

func buildHostileZip(t testing.TB, entries []zipEntry) []byte {
	t.Helper()
	return buildZipEntries(t, entries)
}

// validTarBinary is the benign entry added beside every hostile one.
func validTarBinary() tarEntry {
	return tarEntry{name: "grant", body: fixtureBinaryContents}
}

func validZipBinary() zipEntry {
	return zipEntry{name: "grant.exe", body: fixtureBinaryContents}
}

// TestCheckArchivePath pins each guard to its own diagnostic. The guards are
// ordered most-specific-first: the UNC arm must be reached before the
// absolute-path arm, because path.Clean collapses "//host/share/x" to
// "/host/share/x" and path.IsAbs would otherwise always win and make the UNC
// arm dead code.
func TestCheckArchivePath(t *testing.T) {
	tests := []struct {
		name            string
		entry           string
		wantErrContains string // empty means the path must be accepted
	}{
		{name: "plain name", entry: "grant"},
		{name: "dot slash prefix", entry: "./grant"},
		{name: "nested name", entry: "nested/dir/grant"},
		{name: "name containing dots", entry: "grant..md"},
		{name: "inner parent segment is cleaned away", entry: "a/../grant"},

		{name: "empty name", entry: hostileEmptyName, wantErrContains: "empty name"},
		{name: "absolute", entry: hostileAbsoluteName, wantErrContains: "illegal absolute path"},
		{name: "traversal", entry: hostileTraversalName, wantErrContains: "illegal path traversal"},
		{name: "backslash traversal", entry: hostileBackslashTraversalName, wantErrContains: "illegal path traversal"},
		{name: "bare parent", entry: "..", wantErrContains: "illegal path traversal"},
		{name: "drive absolute", entry: hostileDriveName, wantErrContains: "illegal drive-absolute path"},
		{name: "lowercase drive", entry: hostileDriveLowerName, wantErrContains: "illegal drive-absolute path"},
		{name: "forward slash drive", entry: hostileDriveSlashName, wantErrContains: "illegal drive-absolute path"},
		{name: "unc", entry: hostileUNCName, wantErrContains: "illegal UNC path"},
		{name: "backslash unc", entry: hostileBackslashUNCName, wantErrContains: "illegal UNC path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkArchivePath(tt.entry)
			if tt.wantErrContains == "" {
				if err != nil {
					t.Fatalf("checkArchivePath(%q) = %v, want nil", tt.entry, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkArchivePath(%q) = nil, want an error containing %q", tt.entry, tt.wantErrContains)
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("checkArchivePath(%q) = %q, want it to contain %q", tt.entry, err, tt.wantErrContains)
			}
		})
	}
}

// TestExtractBinaryRejectsNonRegularEntries pins the highest-severity finding
// in the audit: dropping the `hdr.Typeflag != tar.TypeReg` operand turns a
// zero-length symlink, hardlink or directory entry named "grant" into a
// successful extraction of ZERO bytes. Nothing downstream catches that — the
// checksum covers the archive, not the extracted binary, and applyBinary
// hashes whatever it is handed, so an empty payload verifies against itself
// and self-destructs the installed binary.
//
// The fixtures carry no body, so extraction can only ever produce empty bytes;
// they are never written, linked or followed.
func TestExtractBinaryRejectsNonRegularEntries(t *testing.T) {
	tests := []struct {
		name            string
		assetName       string
		archive         []byte
		wantErrContains string
	}{
		{
			name:      "tar symlink named grant",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildHostileTarGz(t, []tarEntry{
				{name: "grant", typeflag: tar.TypeSymlink, linkname: hostileSymlinkTarget},
			}),
			wantErrContains: "does not contain a grant binary",
		},
		{
			name:      "tar hardlink named grant",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildHostileTarGz(t, []tarEntry{
				{name: "other", body: hostilePayload},
				{name: "grant", typeflag: tar.TypeLink, linkname: "other"},
			}),
			wantErrContains: "does not contain a grant binary",
		},
		{
			name:      "tar directory named grant",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildHostileTarGz(t, []tarEntry{
				{name: "grant/", typeflag: tar.TypeDir},
			}),
			wantErrContains: "does not contain a grant binary",
		},
		{
			name:      "zip directory named grant",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildHostileZip(t, []zipEntry{
				{name: "grant/", mode: fs.ModeDir | 0o755},
			}),
			wantErrContains: "does not contain a grant binary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractBinary(tt.archive, tt.assetName)
			if err == nil {
				t.Fatalf("expected rejection, got %d bytes", len(got))
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErrContains)
			}
		})
	}
}

// TestExtractBinaryRejectsEmptyBinary pins the backstop guard: even a
// well-formed regular entry named "grant" must not extract to zero bytes. It
// is a backstop, not a class fix — it does not stop a malformed non-regular
// entry that carries non-empty bytes, which is why
// TestExtractBinaryRejectsNonRegularEntries stays type-specific.
func TestExtractBinaryRejectsEmptyBinary(t *testing.T) {
	t.Run("tar.gz", func(t *testing.T) {
		archive := buildTarGzEntries(t, []tarEntry{{name: "grant"}})
		got, err := extractBinary(archive, "grant-cli_0.7.0_linux_amd64.tar.gz")
		if err == nil {
			t.Fatalf("expected rejection, got %d bytes", len(got))
		}
		if !strings.Contains(err.Error(), "is empty") {
			t.Errorf("error = %q, want it to mention that the entry is empty", err)
		}
	})

	t.Run("zip", func(t *testing.T) {
		archive := buildZipEntries(t, []zipEntry{{name: "grant.exe"}})
		got, err := extractBinary(archive, "grant-cli_0.7.0_windows_amd64.zip")
		if err == nil {
			t.Fatalf("expected rejection, got %d bytes", len(got))
		}
		if !strings.Contains(err.Error(), "is empty") {
			t.Errorf("error = %q, want it to mention that the entry is empty", err)
		}
	})
}

// TestExtractFromTarGzRejectsOversizeDecoy covers the tar declared-size
// pre-filter specifically. The oversized entry is NOT the binary, so
// readCapped never sees it: only the header check can reject this archive, and
// deleting that check makes the archive extract successfully.
func TestExtractFromTarGzRejectsOversizeDecoy(t *testing.T) {
	withMaxDownloadBytes(t, 64)

	archive := buildTarGzEntries(t, []tarEntry{
		{name: "decoy.bin", body: strings.Repeat("A", 300)},
		validTarBinary(),
	})

	got, err := extractBinary(archive, "grant-cli_0.7.0_linux_amd64.tar.gz")
	if err == nil {
		t.Fatalf("expected rejection, got %d bytes", len(got))
	}
	// "declares" is the header pre-filter's wording; readCapped says "exceeds".
	if !strings.Contains(err.Error(), "declares 300 bytes, over the 64 byte limit") {
		t.Errorf("error = %q, want the tar declared-size rejection", err)
	}
}

// TestExtractFromZipIgnoresOversizeDecoy pins the tar/zip asymmetry as
// INTENTIONAL. The tar size check runs for every entry because tar is a
// stream: reaching the next header means inflating the current entry's body.
// zip.NewReader parses only the central directory and never opens a skipped
// entry (f.Open() is called only for the binary), so an oversized non-binary
// entry costs nothing and is correctly ignored. Do not "fix" this by moving
// the zip check earlier — it would reject archives that are not a threat.
func TestExtractFromZipIgnoresOversizeDecoy(t *testing.T) {
	withMaxDownloadBytes(t, 64)

	archive := buildZipEntries(t, []zipEntry{
		{name: "decoy.bin", body: strings.Repeat("A", 300)},
		validZipBinary(),
	})

	got, err := extractBinary(archive, "grant-cli_0.7.0_windows_amd64.zip")
	if err != nil {
		t.Fatalf("an oversized non-binary zip entry must be ignored, got: %v", err)
	}
	if string(got) != fixtureBinaryContents {
		t.Errorf("extracted %q, want the binary beside the decoy", string(got))
	}
}

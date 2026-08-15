package selfupdate

// Coverage-guided fuzzing for the archive-parsing surface — defensive, like
// archive_security_test.go. grant update feeds these functions bytes it just
// downloaded, so they are the one part of the CLI that parses input an
// attacker could shape. Everything runs in memory: nothing is written, linked,
// followed or executed, and every target asserts that grant REJECTS or safely
// accepts, never that it does anything with the payload.
//
// These targets are cheap under a normal `go test` run: the seed corpus is
// executed as ordinary test cases and nothing more. Extended fuzzing is
// deliberately NOT wired into CI; run it by hand, e.g.
//
//	go test ./internal/selfupdate/ -run=Fuzz -fuzz=FuzzCheckArchivePath -fuzztime=30s
//
// Any input that trips an assertion is written to testdata/fuzz/<target>/ by
// the toolchain; commit that file and it becomes a permanent regression seed.

import (
	"archive/tar"
	"io/fs"
	"path"
	"strings"
	"testing"
)

// FuzzCheckArchivePath asserts the guard's CONTRACT rather than its wording:
// any name it accepts must be relative, non-escaping and not Windows-absolute.
func FuzzCheckArchivePath(f *testing.F) {
	seeds := []string{
		"grant",
		"grant.exe",
		"./grant",
		"nested/dir/grant",
		hostileEmptyName,
		hostileTraversalName,
		hostileBackslashTraversalName,
		hostileAbsoluteName,
		hostileDriveName,
		hostileDriveLowerName,
		hostileDriveSlashName,
		hostileUNCName,
		hostileBackslashUNCName,
		"..",
		"a/../../b",
		"\x00grant",
		strings.Repeat("../", 64) + "grant",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, name string) {
		if err := checkArchivePath(name); err != nil {
			return // rejected: nothing further to prove
		}

		if name == "" {
			t.Fatal("an empty entry name must be rejected")
		}
		normalized := strings.ReplaceAll(name, `\`, "/")
		cleaned := path.Clean(normalized)
		switch {
		case strings.HasPrefix(normalized, "//"):
			t.Fatalf("accepted a UNC path: %q", name)
		case path.IsAbs(cleaned):
			t.Fatalf("accepted an absolute path: %q", name)
		case hasDriveLetter(normalized):
			t.Fatalf("accepted a drive-absolute path: %q", name)
		case cleaned == ".." || strings.HasPrefix(cleaned, "../"):
			t.Fatalf("accepted a traversal path: %q", name)
		}
	})
}

// fuzzMaxDownloadBytes bounds what a single fuzz exec can allocate. The
// production cap is 128 MiB and readCapped will io.ReadAll up to it per exec:
// with the real cap FuzzExtractFromZip collapses to 0 exec/sec on transient
// near-cap inputs (worker RSS ~118 MB) while still reporting PASS, which makes
// its exec count incomparable to the other targets'. Shrinking the cap keeps
// the fuzzer exploring archive SHAPE rather than SIZE. It sits well above every
// seed (the largest body is 4 KiB), so no seed is rejected by the cap itself.
const fuzzMaxDownloadBytes = 64 << 10

// assertExtractInvariant is the property both archive targets share: an
// extractor either fails, or returns a NON-EMPTY binary. A successful
// extraction of zero bytes is the self-destruct case — the checksum covers the
// archive, not the extracted bytes, so empty output would be installed.
func assertExtractInvariant(t *testing.T, got []byte, err error) {
	t.Helper()
	if err != nil {
		if len(got) != 0 {
			t.Fatalf("returned %d bytes alongside an error: %v", len(got), err)
		}
		return
	}
	if len(got) == 0 {
		t.Fatal("reported success with an empty binary")
	}
}

func FuzzExtractFromTarGz(f *testing.F) {
	withMaxDownloadBytes(f, fuzzMaxDownloadBytes)

	good := buildTarGzEntries(f, []tarEntry{{name: "grant", body: fixtureBinaryContents}})
	seeds := [][]byte{
		good,
		good[:len(good)/2], // truncated gzip stream
		[]byte("not a gzip stream"),
		nil,
		buildTarGzEntries(f, []tarEntry{{name: hostileTraversalName, body: hostilePayload}, {name: "grant", body: fixtureBinaryContents}}),
		buildTarGzEntries(f, []tarEntry{{name: hostileUNCName, body: hostilePayload}, {name: "grant", body: fixtureBinaryContents}}),
		buildTarGzEntries(f, []tarEntry{{name: hostileDriveName, body: hostilePayload}, {name: "grant", body: fixtureBinaryContents}}),
		buildTarGzEntries(f, []tarEntry{{name: "grant", typeflag: tar.TypeSymlink, linkname: hostileSymlinkTarget}}),
		buildTarGzEntries(f, []tarEntry{{name: "grant", typeflag: tar.TypeDir}}),
		buildTarGzEntries(f, []tarEntry{{name: "grant"}}), // zero-length binary
		buildTarGzEntries(f, []tarEntry{{name: "grant", body: strings.Repeat("A", 4096)}}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, archive []byte) {
		got, err := extractFromTarGz(archive)
		assertExtractInvariant(t, got, err)
	})
}

func FuzzExtractFromZip(f *testing.F) {
	withMaxDownloadBytes(f, fuzzMaxDownloadBytes)

	good := buildZipEntries(f, []zipEntry{{name: "grant.exe", body: fixtureBinaryContents}})
	seeds := [][]byte{
		good,
		good[:len(good)/2], // truncated central directory
		[]byte("not a zip file"),
		nil,
		buildZipEntries(f, []zipEntry{{name: hostileTraversalName, body: hostilePayload}, {name: "grant.exe", body: fixtureBinaryContents}}),
		buildZipEntries(f, []zipEntry{{name: hostileUNCName, body: hostilePayload}, {name: "grant.exe", body: fixtureBinaryContents}}),
		buildZipEntries(f, []zipEntry{{name: hostileDriveName, body: hostilePayload}, {name: "grant.exe", body: fixtureBinaryContents}}),
		buildZipEntries(f, []zipEntry{{name: "grant/", mode: fs.ModeDir | 0o755}}),
		buildZipEntries(f, []zipEntry{{name: "grant.exe"}}), // zero-length binary
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, archive []byte) {
		got, err := extractFromZip(archive)
		assertExtractInvariant(t, got, err)
	})
}

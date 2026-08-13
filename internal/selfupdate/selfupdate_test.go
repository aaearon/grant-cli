package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssetNameFor(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		goarch  string
		version string
		want    string
	}{
		{name: "linux amd64", goos: "linux", goarch: "amd64", version: "0.7.0", want: "grant-cli_0.7.0_linux_amd64.tar.gz"},
		{name: "linux arm64", goos: "linux", goarch: "arm64", version: "0.7.0", want: "grant-cli_0.7.0_linux_arm64.tar.gz"},
		{name: "darwin amd64", goos: "darwin", goarch: "amd64", version: "0.7.0", want: "grant-cli_0.7.0_darwin_amd64.tar.gz"},
		{name: "darwin arm64", goos: "darwin", goarch: "arm64", version: "1.10.2", want: "grant-cli_1.10.2_darwin_arm64.tar.gz"},
		{name: "windows amd64 is zip", goos: "windows", goarch: "amd64", version: "0.7.0", want: "grant-cli_0.7.0_windows_amd64.zip"},
		{name: "windows arm64 is zip", goos: "windows", goarch: "arm64", version: "0.7.0", want: "grant-cli_0.7.0_windows_arm64.zip"},
		{name: "tag with v prefix is normalised", goos: "linux", goarch: "amd64", version: "v0.7.0", want: "grant-cli_0.7.0_linux_amd64.tar.gz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := assetNameFor(tt.goos, tt.goarch, tt.version); got != tt.want {
				t.Errorf("assetNameFor(%q, %q, %q) = %q, want %q", tt.goos, tt.goarch, tt.version, got, tt.want)
			}
		})
	}
}

const latestReleaseFixture = `{
  "tag_name": "v0.7.0",
  "assets": [
    {"name": "checksums.txt", "browser_download_url": "%[1]s/download/checksums.txt"},
    {"name": "grant-cli_0.7.0_linux_amd64.tar.gz", "browser_download_url": "%[1]s/download/grant-cli_0.7.0_linux_amd64.tar.gz"},
    {"name": "grant-cli_0.7.0_windows_amd64.zip", "browser_download_url": "%[1]s/download/grant-cli_0.7.0_windows_amd64.zip"}
  ]
}`

func TestFetchLatestRelease(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		wantErrHas string
		wantTag    string
	}{
		{
			name:    "happy path",
			status:  http.StatusOK,
			body:    latestReleaseFixture,
			wantTag: "v0.7.0",
		},
		{
			name:       "not found",
			status:     http.StatusNotFound,
			body:       `{"message":"Not Found"}`,
			wantErr:    true,
			wantErrHas: "404",
		},
		{
			name:       "rate limited",
			status:     http.StatusForbidden,
			body:       `{"message":"API rate limit exceeded for 1.2.3.4."}`,
			wantErr:    true,
			wantErrHas: "rate limit",
		},
		{
			name:       "malformed json",
			status:     http.StatusOK,
			body:       `{"tag_name": `,
			wantErr:    true,
			wantErrHas: "decode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				fmt.Fprintf(w, tt.body, "http://example.invalid")
			}))
			defer srv.Close()

			u := New("aaearon/grant-cli")
			u.apiBaseURL = srv.URL

			rel, err := u.fetchLatestRelease(t.Context())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got release %+v", rel)
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErrHas)) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rel.TagName != tt.wantTag {
				t.Errorf("tag = %q, want %q", rel.TagName, tt.wantTag)
			}
			if gotPath != "/repos/aaearon/grant-cli/releases/latest" {
				t.Errorf("requested path = %q", gotPath)
			}
			if len(rel.Assets) != 3 {
				t.Fatalf("expected 3 assets, got %d", len(rel.Assets))
			}
		})
	}
}

func TestReleaseAssetURL(t *testing.T) {
	rel := &ghRelease{
		TagName: "v0.7.0",
		Assets: []ghAsset{
			{Name: "checksums.txt", URL: "https://example.invalid/checksums.txt"},
			{Name: "grant-cli_0.7.0_linux_amd64.tar.gz", URL: "https://example.invalid/linux.tar.gz"},
		},
	}

	got, err := rel.assetURL("grant-cli_0.7.0_linux_amd64.tar.gz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.invalid/linux.tar.gz" {
		t.Errorf("got %q", got)
	}

	if _, err := rel.assetURL("grant-cli_0.7.0_plan9_amd64.tar.gz"); err == nil {
		t.Error("expected error for missing asset, got nil")
	}
}

func TestVerifyChecksum(t *testing.T) {
	payload := []byte("fake archive bytes")
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])

	tests := []struct {
		name      string
		checksums string
		filename  string
		data      []byte
		wantErr   bool
	}{
		{
			name:      "match",
			checksums: good + "  grant-cli_0.7.0_linux_amd64.tar.gz\n",
			filename:  "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:      payload,
		},
		{
			name: "match among several lines",
			checksums: "0000000000000000000000000000000000000000000000000000000000000000  checksums-other.txt\n" +
				good + "  grant-cli_0.7.0_linux_amd64.tar.gz\n",
			filename: "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:     payload,
		},
		{
			name:      "GNU binary mode marker",
			checksums: good + " *grant-cli_0.7.0_linux_amd64.tar.gz\n",
			filename:  "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:      payload,
		},
		{
			name:      "CRLF line endings",
			checksums: good + "  grant-cli_0.7.0_linux_amd64.tar.gz\r\n",
			filename:  "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:      payload,
		},
		{
			name:      "mismatch",
			checksums: "0000000000000000000000000000000000000000000000000000000000000000  grant-cli_0.7.0_linux_amd64.tar.gz\n",
			filename:  "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:      payload,
			wantErr:   true,
		},
		{
			name:      "filename absent",
			checksums: good + "  some-other-file.tar.gz\n",
			filename:  "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:      payload,
			wantErr:   true,
		},
		{
			name:      "malformed line",
			checksums: "deadbeef\n",
			filename:  "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:      payload,
			wantErr:   true,
		},
		{
			name:      "empty checksums",
			checksums: "",
			filename:  "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:      payload,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyChecksum([]byte(tt.checksums), tt.filename, tt.data)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// buildTarGz builds an in-memory tar.gz archive from name -> contents.
func buildTarGz(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e[0], Mode: 0o755, Size: int64(len(e[1])), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(e[1])); err != nil {
			t.Fatalf("write tar body: %v", err)
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

// buildZip builds an in-memory zip archive from name -> contents.
func buildZip(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e[0])
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := w.Write([]byte(e[1])); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func TestExtractBinary(t *testing.T) {
	const binContents = "\x7fELF fake grant binary"

	tests := []struct {
		name      string
		assetName string
		archive   []byte
		wantErr   bool
		want      string
	}{
		{
			name:      "tar.gz with decoy files",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{"README.md", "not the binary"},
				{"LICENSE", "MIT"},
				{"grant", binContents},
			}),
			want: binContents,
		},
		{
			name:      "zip with decoy files",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZip(t, [][2]string{
				{"README.md", "not the binary"},
				{"grant.exe", binContents},
			}),
			want: binContents,
		},
		{
			name:      "tar.gz path traversal rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{"../evil", "pwned"},
				{"grant", binContents},
			}),
			wantErr: true,
		},
		{
			name:      "zip path traversal rejected",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZip(t, [][2]string{
				{"../evil", "pwned"},
				{"grant.exe", binContents},
			}),
			wantErr: true,
		},
		{
			name:      "tar.gz absolute path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{"/etc/passwd", "pwned"},
			}),
			wantErr: true,
		},
		{
			name:      "tar.gz windows drive-absolute path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{`C:\grant.exe`, "pwned"},
			}),
			wantErr: true,
		},
		{
			name:      "zip windows drive-absolute path rejected",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZip(t, [][2]string{
				{`C:\grant.exe`, "pwned"},
			}),
			wantErr: true,
		},
		{
			name:      "tar.gz UNC path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive:   buildTarGz(t, [][2]string{{"//host/share/grant", "pwned"}}),
			wantErr:   true,
		},
		{
			name:      "nested binary is not selected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive:   buildTarGz(t, [][2]string{{"nested/dir/grant", "pwned"}}),
			wantErr:   true,
		},
		{
			name:      "dot-slash prefixed binary is accepted",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive:   buildTarGz(t, [][2]string{{"./grant", binContents}}),
			want:      binContents,
		},
		{
			name:      "two candidate binaries rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{"grant", binContents},
				{"grant.exe", "a different binary"},
			}),
			wantErr: true,
		},
		{
			name:      "zip with two candidate binaries rejected",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZip(t, [][2]string{
				{"grant.exe", binContents},
				{"grant", "a different binary"},
			}),
			wantErr: true,
		},
		{
			name:      "tar.gz without binary",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive:   buildTarGz(t, [][2]string{{"README.md", "nope"}}),
			wantErr:   true,
		},
		{
			name:      "zip without binary",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive:   buildZip(t, [][2]string{{"README.md", "nope"}}),
			wantErr:   true,
		},
		{
			name:      "corrupt gzip",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive:   []byte("not a gzip stream"),
			wantErr:   true,
		},
		{
			name:      "corrupt zip",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive:   []byte("not a zip file"),
			wantErr:   true,
		},
		{
			name:      "unknown archive format",
			assetName: "grant-cli_0.7.0_linux_amd64.rar",
			archive:   []byte("whatever"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractBinary(tt.archive, tt.assetName)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %d bytes", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("extracted %q, want %q", string(got), tt.want)
			}
		})
	}
}

// newFixtureServer serves a GitHub releases/latest response plus the referenced assets.
func newFixtureServer(t *testing.T, archiveName string, archive, checksums []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/repos/aaearon/grant-cli/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v0.7.0","assets":[
			{"name":"checksums.txt","browser_download_url":"%[1]s/download/checksums.txt"},
			{"name":%[2]q,"browser_download_url":"%[1]s/download/%[2]s"}
		]}`, srv.URL, archiveName)
	})
	mux.HandleFunc("/download/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write(checksums) //nolint:errcheck // test server
	})
	mux.HandleFunc("/download/"+archiveName, func(w http.ResponseWriter, r *http.Request) {
		w.Write(archive) //nolint:errcheck // test server
	})
	return srv
}

func checksumsFor(name string, data []byte) []byte {
	sum := sha256.Sum256(data)
	return fmt.Appendf(nil, "%s  %s\n", hex.EncodeToString(sum[:]), name)
}

func TestUpdateSelf(t *testing.T) {
	const newBinary = "brand new grant binary"
	archiveName := "grant-cli_0.7.0_linux_amd64.tar.gz"
	archive := buildTarGz(t, [][2]string{{"grant", newBinary}})

	t.Run("already up to date", func(t *testing.T) {
		srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))
		u := New("aaearon/grant-cli")
		u.apiBaseURL = srv.URL
		u.goos, u.goarch = "linux", "amd64"

		applied := false
		u.applyFn = func(b []byte) error { applied = true; return nil }

		newVer, updated, err := u.UpdateSelf(t.Context(), "0.7.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated {
			t.Error("expected updated=false")
		}
		if applied {
			t.Error("apply must not run when already up to date")
		}
		if newVer != "0.7.0" {
			t.Errorf("newVersion = %q, want 0.7.0", newVer)
		}
	})

	t.Run("newer version applied", func(t *testing.T) {
		srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))
		u := New("aaearon/grant-cli")
		u.apiBaseURL = srv.URL
		u.goos, u.goarch = "linux", "amd64"

		var got []byte
		u.applyFn = func(b []byte) error { got = b; return nil }

		newVer, updated, err := u.UpdateSelf(t.Context(), "0.6.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !updated {
			t.Error("expected updated=true")
		}
		if newVer != "0.7.0" {
			t.Errorf("newVersion = %q, want 0.7.0", newVer)
		}
		if string(got) != newBinary {
			t.Errorf("applied %q, want %q", string(got), newBinary)
		}
	})

	t.Run("checksum mismatch aborts before apply", func(t *testing.T) {
		bad := checksumsFor(archiveName, []byte("different bytes entirely"))
		srv := newFixtureServer(t, archiveName, archive, bad)
		u := New("aaearon/grant-cli")
		u.apiBaseURL = srv.URL
		u.goos, u.goarch = "linux", "amd64"

		applied := false
		u.applyFn = func(b []byte) error { applied = true; return nil }

		if _, _, err := u.UpdateSelf(t.Context(), "0.6.1"); err == nil {
			t.Fatal("expected checksum error, got nil")
		}
		if applied {
			t.Error("apply must not run when the checksum does not match")
		}
	})

	t.Run("no asset for platform", func(t *testing.T) {
		srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))
		u := New("aaearon/grant-cli")
		u.apiBaseURL = srv.URL
		u.goos, u.goarch = "plan9", "386"
		u.applyFn = func(b []byte) error { return nil }

		if _, _, err := u.UpdateSelf(t.Context(), "0.6.1"); err == nil {
			t.Fatal("expected error for unavailable asset, got nil")
		}
	})

	t.Run("invalid current version", func(t *testing.T) {
		srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))
		u := New("aaearon/grant-cli")
		u.apiBaseURL = srv.URL
		u.applyFn = func(b []byte) error { return nil }

		if _, _, err := u.UpdateSelf(t.Context(), "not-a-version"); err == nil {
			t.Fatal("expected error for invalid current version, got nil")
		}
	})

	t.Run("apply error propagated", func(t *testing.T) {
		srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))
		u := New("aaearon/grant-cli")
		u.apiBaseURL = srv.URL
		u.goos, u.goarch = "linux", "amd64"
		u.applyFn = func(b []byte) error { return errTestApply }

		if _, _, err := u.UpdateSelf(t.Context(), "0.6.1"); err == nil {
			t.Fatal("expected apply error, got nil")
		}
	})
}

// withSmallCap shrinks the download/decompression cap for a test.
func withSmallCap(t *testing.T, limit int64) {
	t.Helper()
	orig := maxDownloadBytes
	maxDownloadBytes = limit
	t.Cleanup(func() { maxDownloadBytes = orig })
}

// TestReadCappedDetectsOversize pins the boundary bug io.LimitReader hides: a
// source longer than the cap must be an error, never a successful short read.
func TestReadCappedDetectsOversize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		limit   int64
		wantErr bool
		want    string
	}{
		{name: "under the limit", input: "abcd", limit: 8, want: "abcd"},
		{name: "exactly at the limit", input: "abcdefgh", limit: 8, want: "abcdefgh"},
		{name: "one byte over the limit", input: "abcdefghi", limit: 8, wantErr: true},
		{name: "far over the limit", input: strings.Repeat("x", 1000), limit: 8, wantErr: true},
		{name: "empty", input: "", limit: 8, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readCapped(strings.NewReader(tt.input), tt.limit, "test input")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %d bytes", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

// TestExtractBinaryRejectsOversizedEntry covers the critical case: a
// checksum-valid archive whose *decompressed* binary exceeds the cap must be
// rejected, not silently truncated and installed.
func TestExtractBinaryRejectsOversizedEntry(t *testing.T) {
	withSmallCap(t, 64)
	big := strings.Repeat("A", 300)

	t.Run("tar.gz", func(t *testing.T) {
		archive := buildTarGz(t, [][2]string{{"grant", big}})
		got, err := extractBinary(archive, "grant-cli_0.7.0_linux_amd64.tar.gz")
		if err == nil {
			t.Fatalf("expected error, got %d bytes", len(got))
		}
		if !strings.Contains(err.Error(), "limit") {
			t.Errorf("error should mention the limit: %v", err)
		}
	})

	t.Run("zip", func(t *testing.T) {
		archive := buildZip(t, [][2]string{{"grant.exe", big}})
		got, err := extractBinary(archive, "grant-cli_0.7.0_windows_amd64.zip")
		if err == nil {
			t.Fatalf("expected error, got %d bytes", len(got))
		}
		if !strings.Contains(err.Error(), "limit") {
			t.Errorf("error should mention the limit: %v", err)
		}
	})

	t.Run("entry exactly at the limit still extracts", func(t *testing.T) {
		exact := strings.Repeat("A", 64)
		archive := buildTarGz(t, [][2]string{{"grant", exact}})
		got, err := extractBinary(archive, "grant-cli_0.7.0_linux_amd64.tar.gz")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != exact {
			t.Errorf("extracted %d bytes, want %d", len(got), len(exact))
		}
	})
}

// TestExtractBinaryRejectsTruncatedEntry covers a tar whose header declares
// more bytes than the stream actually carries.
func TestExtractBinaryRejectsTruncatedEntry(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := strings.Repeat("B", 4096)
	if err := tw.WriteHeader(&tar.Header{Name: "grant", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	// Chop the gzip stream mid-entry so the declared 4096 bytes are not there.
	truncated := buf.Bytes()[:buf.Len()/2]
	if _, err := extractBinary(truncated, "grant-cli_0.7.0_linux_amd64.tar.gz"); err == nil {
		t.Fatal("expected an error for a truncated archive, got nil")
	}
}

// TestDownloadRejectsOversizeBody pins the same boundary on the HTTP path.
func TestDownloadRejectsOversizeBody(t *testing.T) {
	withSmallCap(t, 32)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 4096))
	}))
	defer srv.Close()

	u := New("aaearon/grant-cli")
	if _, err := u.download(t.Context(), srv.URL); err == nil {
		t.Fatal("expected an error for an oversized download, got nil")
	}
}

// TestUpdateSelfRejectsOversizedBinary is the end-to-end guard: the archive
// checksum is valid, but the binary inside is too big, so nothing is applied.
func TestUpdateSelfRejectsOversizedBinary(t *testing.T) {
	withSmallCap(t, 128)

	archiveName := "grant-cli_0.7.0_linux_amd64.tar.gz"
	archive := buildTarGz(t, [][2]string{{"grant", strings.Repeat("A", 4096)}})
	srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))

	u := New("aaearon/grant-cli")
	u.apiBaseURL = srv.URL
	u.goos, u.goarch = "linux", "amd64"

	applied := false
	u.applyFn = func(b []byte) error { applied = true; return nil }

	if _, _, err := u.UpdateSelf(t.Context(), "0.6.1"); err == nil {
		t.Fatal("expected an error for an oversized binary, got nil")
	}
	if applied {
		t.Error("an oversized binary must never reach the apply step")
	}
}

// TestUpdateSelfPrereleaseCanUpdate is the regression guard for the parser: a
// pre-release build must be able to update to the release.
func TestUpdateSelfPrereleaseCanUpdate(t *testing.T) {
	archiveName := "grant-cli_0.7.0_linux_amd64.tar.gz"
	archive := buildTarGz(t, [][2]string{{"grant", "new binary"}})
	srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))

	u := New("aaearon/grant-cli")
	u.apiBaseURL = srv.URL
	u.goos, u.goarch = "linux", "amd64"
	u.applyFn = func(b []byte) error { return nil }

	latest, updated, err := u.UpdateSelf(t.Context(), "0.7.0-rc.1")
	if err != nil {
		t.Fatalf("a pre-release build must be able to update: %v", err)
	}
	if !updated {
		t.Error("expected the pre-release to update to the release")
	}
	if latest != "0.7.0" {
		t.Errorf("latest = %q, want 0.7.0", latest)
	}
}

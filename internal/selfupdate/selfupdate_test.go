package selfupdate

import (
	"archive/tar"
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

			u := New("aaearon/grant-cli", "v0.6.1")
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

	// wantErrContains, not wantErr: a malformed line that is skipped instead of
	// rejected still ends in an error ("has no entry for"), so only the
	// message can tell the two apart.
	tests := []struct {
		name            string
		checksums       string
		filename        string
		data            []byte
		wantErrContains string
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
			name:            "mismatch",
			checksums:       "0000000000000000000000000000000000000000000000000000000000000000  grant-cli_0.7.0_linux_amd64.tar.gz\n",
			filename:        "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:            payload,
			wantErrContains: "checksum mismatch",
		},
		{
			name:            "filename absent",
			checksums:       good + "  some-other-file.tar.gz\n",
			filename:        "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:            payload,
			wantErrContains: "has no entry for",
		},
		{
			name:            "malformed line with one field",
			checksums:       "deadbeef\n",
			filename:        "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:            payload,
			wantErrContains: "malformed line",
		},
		{
			name:            "malformed line with three fields",
			checksums:       good + "  extra  grant-cli_0.7.0_linux_amd64.tar.gz\n",
			filename:        "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:            payload,
			wantErrContains: "malformed line",
		},
		{
			name:            "empty checksums",
			checksums:       "",
			filename:        "grant-cli_0.7.0_linux_amd64.tar.gz",
			data:            payload,
			wantErrContains: "has no entry for",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyChecksum([]byte(tt.checksums), tt.filename, tt.data)
			if tt.wantErrContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tt.wantErrContains)
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErrContains)
			}
		})
	}
}

// buildTarGz builds an in-memory tar.gz archive from name -> contents. It is a
// convenience wrapper over buildTarGzEntries (archive_security_test.go) for the
// common case of well-formed regular files; tests that need a non-regular type
// flag, a link name or a lying declared size call buildTarGzEntries directly.
func buildTarGz(t testing.TB, entries [][2]string) []byte {
	t.Helper()
	full := make([]tarEntry, 0, len(entries))
	for _, e := range entries {
		full = append(full, tarEntry{name: e[0], body: e[1]})
	}
	return buildTarGzEntries(t, full)
}

// buildZip builds an in-memory zip archive from name -> contents. Wrapper over
// buildZipEntries, mirroring buildTarGz.
func buildZip(t testing.TB, entries [][2]string) []byte {
	t.Helper()
	full := make([]zipEntry, 0, len(entries))
	for _, e := range entries {
		full = append(full, zipEntry{name: e[0], body: e[1]})
	}
	return buildZipEntries(t, full)
}

// TestExtractBinary drives the whole extractor. Two conventions matter here:
//
//   - wantErrContains, not a bare wantErr bool. Several of the path guards are
//     interchangeable as far as "an error happened" is concerned, so only
//     message discrimination can tell them apart - and a guard that is silently
//     replaced by a later, more general one is exactly the regression this
//     table exists to catch.
//   - every hostile entry sits BESIDE a valid "grant". Without it the archive
//     also fails the "does not contain a grant binary" check, so removing the
//     guard under test still produces an error and the case proves nothing.
func TestExtractBinary(t *testing.T) {
	const binContents = "\x7fELF fake grant binary"

	tests := []struct {
		name            string
		assetName       string
		archive         []byte
		wantErrContains string // empty means the extraction must succeed
		want            string
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
				{hostileTraversalName, hostilePayload},
				{"grant", binContents},
			}),
			wantErrContains: "illegal path traversal",
		},
		{
			name:      "tar.gz backslash traversal rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{hostileBackslashTraversalName, hostilePayload},
				{"grant", binContents},
			}),
			wantErrContains: "illegal path traversal",
		},
		{
			name:      "zip path traversal rejected",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZip(t, [][2]string{
				{hostileTraversalName, hostilePayload},
				{"grant.exe", binContents},
			}),
			wantErrContains: "illegal path traversal",
		},
		{
			name:      "tar.gz absolute path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{hostileAbsoluteName, hostilePayload},
				{"grant", binContents},
			}),
			wantErrContains: "illegal absolute path",
		},
		{
			name:      "tar.gz windows drive-absolute path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{hostileDriveName, hostilePayload},
				{"grant", binContents},
			}),
			wantErrContains: "illegal drive-absolute path",
		},
		{
			name:      "tar.gz lowercase drive-absolute path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{hostileDriveLowerName, hostilePayload},
				{"grant", binContents},
			}),
			wantErrContains: "illegal drive-absolute path",
		},
		{
			name:      "tar.gz forward-slash drive-absolute path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{hostileDriveSlashName, hostilePayload},
				{"grant", binContents},
			}),
			wantErrContains: "illegal drive-absolute path",
		},
		{
			name:      "zip windows drive-absolute path rejected",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZip(t, [][2]string{
				{hostileDriveName, hostilePayload},
				{"grant.exe", binContents},
			}),
			wantErrContains: "illegal drive-absolute path",
		},
		{
			name:      "tar.gz UNC path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{hostileUNCName, hostilePayload},
				{"grant", binContents},
			}),
			wantErrContains: "illegal UNC path",
		},
		{
			name:      "tar.gz backslash UNC path rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGz(t, [][2]string{
				{hostileBackslashUNCName, hostilePayload},
				{"grant", binContents},
			}),
			wantErrContains: "illegal UNC path",
		},
		{
			name:      "zip UNC path rejected",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZip(t, [][2]string{
				{hostileUNCName, hostilePayload},
				{"grant.exe", binContents},
			}),
			wantErrContains: "illegal UNC path",
		},
		{
			name:      "tar.gz empty entry name rejected",
			assetName: "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive: buildTarGzEntries(t, []tarEntry{
				{name: hostileEmptyName, body: hostilePayload},
				{name: "grant", body: binContents},
			}),
			wantErrContains: "empty name",
		},
		{
			name:      "zip empty entry name rejected",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZipEntries(t, []zipEntry{
				{name: hostileEmptyName, body: hostilePayload},
				{name: "grant.exe", body: binContents},
			}),
			wantErrContains: "empty name",
		},
		{
			name:            "nested binary is not selected",
			assetName:       "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive:         buildTarGz(t, [][2]string{{"nested/dir/grant", hostilePayload}}),
			wantErrContains: "does not contain a grant binary",
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
			wantErrContains: "more than one grant binary",
		},
		{
			name:      "zip with two candidate binaries rejected",
			assetName: "grant-cli_0.7.0_windows_amd64.zip",
			archive: buildZip(t, [][2]string{
				{"grant.exe", binContents},
				{"grant", "a different binary"},
			}),
			wantErrContains: "more than one grant binary",
		},
		{
			name:            "tar.gz without binary",
			assetName:       "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive:         buildTarGz(t, [][2]string{{"README.md", "nope"}}),
			wantErrContains: "does not contain a grant binary",
		},
		{
			name:            "zip without binary",
			assetName:       "grant-cli_0.7.0_windows_amd64.zip",
			archive:         buildZip(t, [][2]string{{"README.md", "nope"}}),
			wantErrContains: "does not contain a grant binary",
		},
		{
			name:            "corrupt gzip",
			assetName:       "grant-cli_0.7.0_linux_amd64.tar.gz",
			archive:         []byte("not a gzip stream"),
			wantErrContains: "failed to open gzip stream",
		},
		{
			name:            "corrupt zip",
			assetName:       "grant-cli_0.7.0_windows_amd64.zip",
			archive:         []byte("not a zip file"),
			wantErrContains: "failed to open zip archive",
		},
		{
			// Kills a default arm that falls through to tar.gz: that would
			// fail on the gzip header instead, with a different message.
			name:            "unknown archive format",
			assetName:       "grant-cli_0.7.0_linux_amd64.rar",
			archive:         []byte("whatever"),
			wantErrContains: "unsupported archive format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractBinary(tt.archive, tt.assetName)
			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got %d bytes", tt.wantErrContains, len(got))
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("error = %q, want it to contain %q", err, tt.wantErrContains)
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

// fixtureServerOpts configures newFixtureServerWith. A nil handler keeps the
// default (the same behavior newFixtureServer provides); releaseBody replaces
// only the JSON body while keeping the default 200 handler.
type fixtureServerOpts struct {
	archiveName string
	archive     []byte
	checksums   []byte

	// releaseBody receives the server URL and returns the releases/latest
	// body. Ignored when releaseHandler is set.
	releaseBody func(srvURL string) string

	releaseHandler   http.HandlerFunc
	archiveHandler   http.HandlerFunc
	checksumsHandler http.HandlerFunc
}

// newFixtureServerWith is newFixtureServer with per-path handler overrides, so
// tests can drive a non-200 on either download, an empty body, or a release
// payload the happy path never produces. It is a sibling rather than a change
// to newFixtureServer's signature: the simple form has three call sites that
// have no interest in any of this.
func newFixtureServerWith(t *testing.T, opts fixtureServerOpts) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	release := opts.releaseHandler
	if release == nil {
		release = func(w http.ResponseWriter, r *http.Request) {
			if opts.releaseBody != nil {
				fmt.Fprint(w, opts.releaseBody(srv.URL))
				return
			}
			fmt.Fprintf(w, `{"tag_name":"v0.7.0","assets":[
				{"name":"checksums.txt","browser_download_url":"%[1]s/download/checksums.txt"},
				{"name":%[2]q,"browser_download_url":"%[1]s/download/%[2]s"}
			]}`, srv.URL, opts.archiveName)
		}
	}
	checksums := opts.checksumsHandler
	if checksums == nil {
		checksums = func(w http.ResponseWriter, r *http.Request) {
			w.Write(opts.checksums) //nolint:errcheck // test server
		}
	}
	archive := opts.archiveHandler
	if archive == nil {
		archive = func(w http.ResponseWriter, r *http.Request) {
			w.Write(opts.archive) //nolint:errcheck // test server
		}
	}

	mux.HandleFunc("/repos/aaearon/grant-cli/releases/latest", release)
	mux.HandleFunc("/download/checksums.txt", checksums)
	mux.HandleFunc("/download/"+opts.archiveName, archive)
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
		u := New("aaearon/grant-cli", "v0.6.1")
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
		u := New("aaearon/grant-cli", "v0.6.1")
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
		u := New("aaearon/grant-cli", "v0.6.1")
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
		u := New("aaearon/grant-cli", "v0.6.1")
		u.apiBaseURL = srv.URL
		u.goos, u.goarch = "plan9", "386"
		u.applyFn = func(b []byte) error { return nil }

		if _, _, err := u.UpdateSelf(t.Context(), "0.6.1"); err == nil {
			t.Fatal("expected error for unavailable asset, got nil")
		}
	})

	t.Run("invalid current version", func(t *testing.T) {
		srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))
		u := New("aaearon/grant-cli", "v0.6.1")
		u.apiBaseURL = srv.URL
		u.applyFn = func(b []byte) error { return nil }

		if _, _, err := u.UpdateSelf(t.Context(), "not-a-version"); err == nil {
			t.Fatal("expected error for invalid current version, got nil")
		}
	})

	t.Run("apply error propagated", func(t *testing.T) {
		srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))
		u := New("aaearon/grant-cli", "v0.6.1")
		u.apiBaseURL = srv.URL
		u.goos, u.goarch = "linux", "amd64"
		u.applyFn = func(b []byte) error { return errTestApply }

		if _, _, err := u.UpdateSelf(t.Context(), "0.6.1"); err == nil {
			t.Fatal("expected apply error, got nil")
		}
	})
}

// TestFetchLatestReleaseRejectsBadPayloads covers the two release-payload
// failures the happy path cannot reach. Both assert the SPECIFIC message: an
// empty body also produces an empty tag_name, so a test that only demanded
// "some error" would pass with the JSON error check deleted.
func TestFetchLatestReleaseRejectsBadPayloads(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantErrContains string
	}{
		{
			name:            "empty body",
			body:            "",
			wantErrContains: "failed to decode GitHub release response",
		},
		{
			name:            "empty tag_name",
			body:            `{"tag_name":"","assets":[]}`,
			wantErrContains: "no tag_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.body
			srv := newFixtureServerWith(t, fixtureServerOpts{
				archiveName: "grant-cli_0.7.0_linux_amd64.tar.gz",
				releaseBody: func(string) string { return body },
			})

			u := New("aaearon/grant-cli", "v0.6.1")
			u.apiBaseURL = srv.URL

			rel, err := u.fetchLatestRelease(t.Context())
			if err == nil {
				t.Fatalf("expected an error, got release %+v", rel)
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErrContains)
			}
		})
	}
}

// TestUpdateSelfFailsOnAssetDownloadStatus covers a non-200 on each of the two
// asset downloads. Neither is reachable through the release-lookup fixture,
// and both must abort before anything is applied.
func TestUpdateSelfFailsOnAssetDownloadStatus(t *testing.T) {
	archiveName := "grant-cli_0.7.0_linux_amd64.tar.gz"
	archive := buildTarGz(t, [][2]string{{"grant", "new binary"}})

	tests := []struct {
		name            string
		mutate          func(o *fixtureServerOpts)
		wantErrContains string
	}{
		{
			name: "archive download returns 500",
			mutate: func(o *fixtureServerOpts) {
				o.archiveHandler = func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			},
			// The status must be named. A 500 with an empty body also trips
			// the empty-download check, so asserting only the "failed to
			// download <asset>" wrapper would pass with the status check
			// deleted.
			wantErrContains: "failed to download " + archiveName + ": download returned status 500",
		},
		{
			name: "checksums download returns 404",
			mutate: func(o *fixtureServerOpts) {
				o.checksumsHandler = func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErrContains: "failed to download checksums.txt: download returned status 404",
		},
		{
			name: "archive download returns an empty body",
			mutate: func(o *fixtureServerOpts) {
				o.archiveHandler = func(w http.ResponseWriter, r *http.Request) {}
			},
			wantErrContains: "failed to download " + archiveName + ": download was empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := fixtureServerOpts{
				archiveName: archiveName,
				archive:     archive,
				checksums:   checksumsFor(archiveName, archive),
			}
			tt.mutate(&opts)
			srv := newFixtureServerWith(t, opts)

			u := New("aaearon/grant-cli", "v0.6.1")
			u.apiBaseURL = srv.URL
			u.goos, u.goarch = "linux", "amd64"

			applied := false
			u.applyFn = func([]byte) error { applied = true; return nil }

			_, _, err := u.UpdateSelf(t.Context(), "0.6.1")
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErrContains)
			}
			if applied {
				t.Error("a failed download must never reach the apply step")
			}
		})
	}
}

// withMaxDownloadBytes shrinks the download/decompression cap for one test and
// restores it via t.Cleanup, so an early t.Fatal cannot leak the change into
// another test. maxDownloadBytes is package-global mutable state: callers of
// this helper MUST NOT call t.Parallel(). It takes testing.TB so the fuzz
// targets can bound each exec through the same seam (see fuzz_test.go).
func withMaxDownloadBytes(t testing.TB, limit int64) {
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
	withMaxDownloadBytes(t, 64)
	big := strings.Repeat("A", 300)

	// The declared-size pre-filters must be what rejects these, not readCapped
	// downstream: "declares" is the pre-filter's wording, "exceeds" is
	// readCapped's. Asserting the exact wording is what keeps the pre-filters
	// from being deleted as redundant.
	t.Run("tar.gz", func(t *testing.T) {
		archive := buildTarGz(t, [][2]string{{"grant", big}})
		got, err := extractBinary(archive, "grant-cli_0.7.0_linux_amd64.tar.gz")
		if err == nil {
			t.Fatalf("expected error, got %d bytes", len(got))
		}
		if !strings.Contains(err.Error(), "declares 300 bytes, over the 64 byte limit") {
			t.Errorf("error should be the tar declared-size rejection: %v", err)
		}
	})

	t.Run("zip", func(t *testing.T) {
		archive := buildZip(t, [][2]string{{"grant.exe", big}})
		got, err := extractBinary(archive, "grant-cli_0.7.0_windows_amd64.zip")
		if err == nil {
			t.Fatalf("expected error, got %d bytes", len(got))
		}
		if !strings.Contains(err.Error(), "declares 300 bytes, over the 64 byte limit") {
			t.Errorf("error should be the zip declared-size rejection: %v", err)
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

// TestExtractBinaryRejectsTruncatedArchive covers a gzip stream that is cut
// short mid-entry.
//
// It pins GZIP-STREAM truncation, and nothing else. In particular it does NOT
// cover the `len(data) != hdr.Size` cross-check in extractFromTarGz: that
// branch is unreachable, because a stream that runs out early fails inside
// readCapped with io.ErrUnexpectedEOF long before the comparison. The
// cross-check is retained as defense in depth with no coverage claimed - see
// the comment on it in selfupdate.go.
func TestExtractBinaryRejectsTruncatedArchive(t *testing.T) {
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
	withMaxDownloadBytes(t, 32)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 4096))
	}))
	defer srv.Close()

	u := New("aaearon/grant-cli", "v0.6.1")
	if _, err := u.download(t.Context(), srv.URL); err == nil {
		t.Fatal("expected an error for an oversized download, got nil")
	}
}

// TestUpdateSelfRejectsOversizedBinary is the end-to-end guard: the archive
// checksum is valid, but the binary inside is too big, so nothing is applied.
func TestUpdateSelfRejectsOversizedBinary(t *testing.T) {
	withMaxDownloadBytes(t, 128)

	archiveName := "grant-cli_0.7.0_linux_amd64.tar.gz"
	archive := buildTarGz(t, [][2]string{{"grant", strings.Repeat("A", 4096)}})
	srv := newFixtureServer(t, archiveName, archive, checksumsFor(archiveName, archive))

	u := New("aaearon/grant-cli", "v0.6.1")
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

	u := New("aaearon/grant-cli", "v0.6.1")
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

// TestRequestsSendUserAgent guards against GitHub's 403 "Must provide a
// User-Agent header": every request the updater makes — the release lookup and
// both asset downloads — must carry one.
func TestRequestsSendUserAgent(t *testing.T) {
	archiveName := "grant-cli_0.7.0_linux_amd64.tar.gz"
	archive := buildTarGz(t, [][2]string{{"grant", "new binary"}})

	seen := map[string]string{}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	checksums := checksumsFor(archiveName, archive)

	mux.HandleFunc("/repos/aaearon/grant-cli/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"tag_name":"v0.7.0","assets":[
			{"name":"checksums.txt","browser_download_url":"%[1]s/download/checksums.txt"},
			{"name":%[2]q,"browser_download_url":"%[1]s/download/%[2]s"}
		]}`, srv.URL, archiveName)
	})
	mux.HandleFunc("/download/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = r.Header.Get("User-Agent")
		w.Write(checksums) //nolint:errcheck // test server
	})
	mux.HandleFunc("/download/"+archiveName, func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = r.Header.Get("User-Agent")
		w.Write(archive) //nolint:errcheck // test server
	})

	u := New("aaearon/grant-cli", "v0.6.1")
	u.apiBaseURL = srv.URL
	u.goos, u.goarch = "linux", "amd64"
	u.applyFn = func(b []byte) error { return nil }

	if _, _, err := u.UpdateSelf(t.Context(), "0.6.1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantPaths := []string{
		"/repos/aaearon/grant-cli/releases/latest",
		"/download/checksums.txt",
		"/download/" + archiveName,
	}
	for _, p := range wantPaths {
		got, ok := seen[p]
		if !ok {
			t.Fatalf("%s was never requested", p)
		}
		if got != "grant-cli/0.6.1" {
			t.Errorf("User-Agent for %s = %q, want %q", p, got, "grant-cli/0.6.1")
		}
	}
}

func TestNewUserAgentFallsBackToDev(t *testing.T) {
	if got := New("aaearon/grant-cli", "").userAgent; got != "grant-cli/dev" {
		t.Errorf("userAgent = %q, want %q", got, "grant-cli/dev")
	}
}

// Package selfupdate implements grant's self-update: GitHub release discovery,
// platform asset selection, SHA-256 checksum verification and archive
// extraction, with the binary replacement itself delegated to
// github.com/minio/selfupdate.
//
// Trust model: checksums.txt is published by GoReleaser alongside the archives
// and is fetched from the same origin as the binary. Verifying it protects
// against truncated or corrupted downloads and CDN/transport tampering. It does
// NOT protect against a compromised GitHub account or release pipeline, since
// an attacker able to replace the archive can also replace checksums.txt.
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"runtime"
	"strings"
	"time"
)

const (
	// projectName matches GoReleaser's project name in the archive filenames.
	projectName = "grant-cli"
	// binaryName is the executable inside the release archive.
	binaryName = "grant"
	// checksumsFile is GoReleaser's checksum.name_template.
	checksumsFile = "checksums.txt"
	// defaultAPIBaseURL is the GitHub REST API root.
	defaultAPIBaseURL = "https://api.github.com"
	// downloadTimeout bounds the whole update operation.
	downloadTimeout = 5 * time.Minute
)

// maxDownloadBytes caps every download and every decompressed entry, guarding
// against decompression bombs (gosec G110).
//
// It is a var ONLY so tests can shrink it; nothing in production code may
// assign to it. Because it is package-global mutable state, any test that
// changes it MUST NOT call t.Parallel(), and MUST go through
// withMaxDownloadBytes so the value is restored via t.Cleanup even on an early
// t.Fatal.
var maxDownloadBytes int64 = 128 << 20 // 128 MiB

// httpDoer allows injecting a stub transport in tests.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ghAsset is a single release asset from the GitHub API.
type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// ghRelease is the subset of the GitHub releases/latest payload grant needs.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// assetURL returns the download URL for the named asset.
func (r *ghRelease) assetURL(name string) (string, error) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("release %s has no asset named %q", r.TagName, name)
}

// Updater checks GitHub Releases and replaces the running binary.
type Updater struct {
	slug       string
	apiBaseURL string
	client     httpDoer
	goos       string
	goarch     string
	// userAgent is sent on every request; GitHub's API rejects requests
	// without one ("Must provide a User-Agent header", 403).
	userAgent string
	// applyFn replaces the running executable; injectable for tests.
	applyFn func(newBinary []byte) error
}

// New creates an Updater for the given "owner/repo" slug. version is the
// running build's version, used only for the User-Agent; an empty value
// becomes "dev".
func New(slug, version string) *Updater {
	v := strings.TrimPrefix(version, "v")
	if v == "" {
		v = "dev"
	}
	return &Updater{
		slug:       slug,
		apiBaseURL: defaultAPIBaseURL,
		client:     &http.Client{Timeout: downloadTimeout},
		goos:       runtime.GOOS,
		goarch:     runtime.GOARCH,
		userAgent:  projectName + "/" + v,
		applyFn:    applyBinary,
	}
}

// UpdateSelf checks for a newer release and, if one exists, downloads,
// verifies and installs it. It returns the latest published version, whether
// the binary was replaced, and any error.
func (u *Updater) UpdateSelf(ctx context.Context, current string) (newVersion string, updated bool, err error) {
	currentVer, err := ParseVersion(current)
	if err != nil {
		return "", false, err
	}

	rel, err := u.fetchLatestRelease(ctx)
	if err != nil {
		return "", false, err
	}

	latestVer, err := ParseVersion(rel.TagName)
	if err != nil {
		return "", false, fmt.Errorf("latest release tag %q: %w", rel.TagName, err)
	}

	if currentVer.Compare(latestVer) >= 0 {
		return latestVer.String(), false, nil
	}

	assetName := assetNameFor(u.goos, u.goarch, latestVer.String())
	assetURL, err := rel.assetURL(assetName)
	if err != nil {
		return "", false, err
	}
	checksumsURL, err := rel.assetURL(checksumsFile)
	if err != nil {
		return "", false, err
	}

	archive, err := u.download(ctx, assetURL)
	if err != nil {
		return "", false, fmt.Errorf("failed to download %s: %w", assetName, err)
	}

	checksums, err := u.download(ctx, checksumsURL)
	if err != nil {
		return "", false, fmt.Errorf("failed to download %s: %w", checksumsFile, err)
	}

	if err := verifyChecksum(checksums, assetName, archive); err != nil {
		return "", false, err
	}

	bin, err := extractBinary(archive, assetName)
	if err != nil {
		return "", false, err
	}

	if err := u.applyFn(bin); err != nil {
		return "", false, fmt.Errorf("failed to replace binary: %w", err)
	}

	return latestVer.String(), true, nil
}

// fetchLatestRelease queries GitHub for the repository's latest release.
func (u *Updater) fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimSuffix(u.apiBaseURL, "/"), u.slug)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to build release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", u.userAgent)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query GitHub releases: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable on close

	body, err := readCapped(resp.Body, maxDownloadBytes, "GitHub release response")
	if err != nil {
		return nil, fmt.Errorf("failed to read GitHub response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned %d for %s: %s", resp.StatusCode, url, strings.TrimSpace(string(body)))
	}

	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub release response: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("GitHub release response has no tag_name")
	}
	return &rel, nil
}

// download fetches a URL into memory, capped at maxDownloadBytes.
func (u *Updater) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to build download request: %w", err)
	}
	req.Header.Set("User-Agent", u.userAgent)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable on close

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	data, err := readCapped(resp.Body, maxDownloadBytes, "download")
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("download was empty")
	}
	return data, nil
}

// readCapped reads at most limit bytes and fails if the source has more to
// give. io.LimitReader alone reports a *successful* short read when the input
// is longer than the cap, which would silently truncate a binary; probing for
// one extra byte turns that into an error (gosec G110 without the silent
// truncation hazard).
func readCapped(r io.Reader, limit int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) < limit {
		return data, nil
	}
	var probe [1]byte
	switch n, err := io.ReadFull(r, probe[:]); {
	case n > 0:
		return nil, fmt.Errorf("%s exceeds the %d byte limit", what, limit)
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return data, nil
	default:
		return nil, err
	}
}

// assetNameFor builds the GoReleaser archive name for a platform.
// Mirrors .goreleaser.yaml: default archive name_template with a zip override
// on Windows.
func assetNameFor(goos, goarch, version string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("%s_%s_%s_%s%s", projectName, strings.TrimPrefix(version, "v"), goos, goarch, ext)
}

// verifyChecksum checks data against the entry for filename in a GoReleaser
// checksums.txt ("<sha256 hex>  <filename>" per line).
func verifyChecksum(checksums []byte, filename string, data []byte) error {
	want := ""
	scanner := bufio.NewScanner(bytes.NewReader(checksums))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("malformed line in %s: %q", checksumsFile, line)
		}
		// GNU coreutils marks binary-mode entries with a leading "*".
		if strings.TrimPrefix(fields[1], "*") == filename {
			want = fields[0]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read %s: %w", checksumsFile, err)
	}
	if want == "" {
		return fmt.Errorf("%s has no entry for %s", checksumsFile, filename)
	}

	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", filename, got, want)
	}
	return nil
}

// extractBinary pulls the grant executable out of a release archive.
func extractBinary(archive []byte, assetName string) ([]byte, error) {
	switch {
	case strings.HasSuffix(assetName, ".tar.gz"):
		return extractFromTarGz(archive)
	case strings.HasSuffix(assetName, ".zip"):
		return extractFromZip(archive)
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", assetName)
	}
}

// isBinaryEntry reports whether an archive entry is the grant executable.
// GoReleaser places the binary at the archive root, so nested entries with the
// same basename are deliberately NOT accepted - matching them would let a
// crafted archive smuggle a different file into the install.
func isBinaryEntry(name string) bool {
	cleaned := path.Clean(strings.ReplaceAll(name, `\`, "/"))
	cleaned = strings.TrimPrefix(cleaned, "./")
	if strings.Contains(cleaned, "/") {
		return false
	}
	return cleaned == binaryName || cleaned == binaryName+".exe"
}

// checkArchivePath rejects absolute paths, drive-absolute Windows paths, UNC
// paths and traversal (gosec G305). Extraction is in-memory, so none of these
// are currently exploitable, but the archive is untrusted input and the
// documented guarantee has to actually hold.
func checkArchivePath(name string) error {
	normalized := strings.ReplaceAll(name, `\`, "/")
	cleaned := path.Clean(normalized)

	switch {
	case name == "":
		return errors.New("archive contains an entry with an empty name")
	// The UNC arm must precede the absolute arm: path.Clean collapses
	// "//host/share/x" to "/host/share/x", so path.IsAbs would always match
	// first and this arm would be unreachable. Specificity before generality -
	// the rejection is the same either way, only the diagnostic differs.
	case strings.HasPrefix(normalized, "//"):
		return fmt.Errorf("archive contains illegal UNC path %q", name)
	case path.IsAbs(cleaned):
		return fmt.Errorf("archive contains illegal absolute path %q", name)
	case hasDriveLetter(normalized):
		return fmt.Errorf("archive contains illegal drive-absolute path %q", name)
	case cleaned == ".." || strings.HasPrefix(cleaned, "../"):
		return fmt.Errorf("archive contains illegal path traversal %q", name)
	}
	return nil
}

// hasDriveLetter reports whether name starts with a Windows drive designator
// such as "C:" - path.IsAbs does not consider these absolute.
func hasDriveLetter(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}
	c := name[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func extractFromTarGz(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip stream: %w", err)
	}
	defer gz.Close() //nolint:errcheck // read-only stream

	var found []byte
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar archive: %w", err)
		}
		if err := checkArchivePath(hdr.Name); err != nil {
			return nil, err
		}
		// Checked for every entry, not just the binary: skipped entries are
		// still decompressed by the next Next() call.
		if hdr.Size > maxDownloadBytes {
			return nil, fmt.Errorf("%s in archive declares %d bytes, over the %d byte limit", hdr.Name, hdr.Size, maxDownloadBytes)
		}
		if hdr.Typeflag != tar.TypeReg || !isBinaryEntry(hdr.Name) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("archive contains more than one %s binary", binaryName)
		}
		data, err := readCapped(tr, maxDownloadBytes, hdr.Name) // gosec G110
		if err != nil {
			return nil, fmt.Errorf("failed to read %s from archive: %w", hdr.Name, err)
		}
		// Defense in depth, and UNREACHABLE by construction: a successful
		// readCapped returns exactly hdr.Size bytes, and a stream that runs
		// out early fails inside readCapped with io.ErrUnexpectedEOF. Kept
		// because the invariant is worth stating, but no test claims coverage
		// of this branch - it cannot be provoked through tar.Reader.
		if int64(len(data)) != hdr.Size {
			return nil, fmt.Errorf("%s in archive is truncated: got %d bytes, header declares %d", hdr.Name, len(data), hdr.Size)
		}
		// A zero-length binary must never reach the apply step: the checksum
		// covers the archive, not the extracted bytes, so an empty payload
		// would be hashed and installed over the working binary. This is a
		// backstop for the type and size guards above, not a replacement.
		if len(data) == 0 {
			return nil, fmt.Errorf("%s in archive is empty", hdr.Name)
		}
		found = data
	}
	if found == nil {
		return nil, fmt.Errorf("archive does not contain a %s binary", binaryName)
	}
	return found, nil
}

func extractFromZip(archive []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip archive: %w", err)
	}

	var found []byte
	for _, f := range zr.File {
		if err := checkArchivePath(f.Name); err != nil {
			return nil, err
		}
		if f.FileInfo().IsDir() || !isBinaryEntry(f.Name) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("archive contains more than one %s binary", binaryName)
		}
		if maxDownloadBytes >= 0 && f.UncompressedSize64 > uint64(maxDownloadBytes) { //nolint:gosec // maxDownloadBytes is a positive constant-derived cap
			return nil, fmt.Errorf("%s in archive declares %d bytes, over the %d byte limit", f.Name, f.UncompressedSize64, maxDownloadBytes)
		}
		data, err := readZipEntry(f)
		if err != nil {
			return nil, err
		}
		// Defense in depth, and UNREACHABLE for the same reason as the tar
		// cross-check above: readCapped either returns the full entry or
		// fails. No test claims coverage of this branch.
		if uint64(len(data)) != f.UncompressedSize64 {
			return nil, fmt.Errorf("%s in archive is truncated: got %d bytes, directory declares %d", f.Name, len(data), f.UncompressedSize64)
		}
		// See extractFromTarGz: an empty payload would be checksum-valid and
		// would self-destruct the installed binary.
		if len(data) == 0 {
			return nil, fmt.Errorf("%s in archive is empty", f.Name)
		}
		found = data
	}
	if found == nil {
		return nil, fmt.Errorf("archive does not contain a %s binary", binaryName)
	}
	return found, nil
}

// readZipEntry reads a single zip entry with the decompression cap applied.
func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open %s in archive: %w", f.Name, err)
	}
	defer rc.Close() //nolint:errcheck // read-only stream

	data, err := readCapped(rc, maxDownloadBytes, f.Name) // gosec G110
	if err != nil {
		return nil, fmt.Errorf("failed to read %s from archive: %w", f.Name, err)
	}
	return data, nil
}

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
	// maxDownloadBytes caps every download and every decompressed entry,
	// guarding against decompression bombs (gosec G110).
	maxDownloadBytes = 128 << 20 // 128 MiB
	// downloadTimeout bounds the whole update operation.
	downloadTimeout = 5 * time.Minute
)

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
	// applyFn replaces the running executable; injectable for tests.
	applyFn func(newBinary []byte) error
}

// New creates an Updater for the given "owner/repo" slug.
func New(slug string) *Updater {
	return &Updater{
		slug:       slug,
		apiBaseURL: defaultAPIBaseURL,
		client:     &http.Client{Timeout: downloadTimeout},
		goos:       runtime.GOOS,
		goarch:     runtime.GOARCH,
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

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query GitHub releases: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable on close

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes))
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

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable on close

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("download was empty")
	}
	return data, nil
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
		if fields[1] == filename {
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
func isBinaryEntry(name string) bool {
	base := path.Base(name)
	return base == binaryName || base == binaryName+".exe"
}

// checkArchivePath rejects absolute paths and traversal (gosec G305).
func checkArchivePath(name string) error {
	cleaned := path.Clean(strings.ReplaceAll(name, `\`, "/"))
	if path.IsAbs(cleaned) || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return fmt.Errorf("archive contains illegal path %q", name)
	}
	return nil
}

func extractFromTarGz(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip stream: %w", err)
	}
	defer gz.Close() //nolint:errcheck // read-only stream

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
		if hdr.Typeflag != tar.TypeReg || !isBinaryEntry(hdr.Name) {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxDownloadBytes)) // gosec G110
		if err != nil {
			return nil, fmt.Errorf("failed to read %s from archive: %w", hdr.Name, err)
		}
		return data, nil
	}
	return nil, fmt.Errorf("archive does not contain a %s binary", binaryName)
}

func extractFromZip(archive []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip archive: %w", err)
	}

	for _, f := range zr.File {
		if err := checkArchivePath(f.Name); err != nil {
			return nil, err
		}
		if f.FileInfo().IsDir() || !isBinaryEntry(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open %s in archive: %w", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxDownloadBytes)) // gosec G110
		closeErr := rc.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read %s from archive: %w", f.Name, err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("failed to close %s in archive: %w", f.Name, closeErr)
		}
		return data, nil
	}
	return nil, fmt.Errorf("archive does not contain a %s binary", binaryName)
}

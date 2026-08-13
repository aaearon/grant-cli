package selfupdate

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a GoReleaser-style MAJOR.MINOR.PATCH version.
// grant only ever emits tags in this shape, so pre-release and build
// metadata are deliberately unsupported.
type Version struct {
	Major int
	Minor int
	Patch int
}

// String renders the version without a leading "v".
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare returns -1 if v < other, 0 if equal, 1 if v > other.
func (v Version) Compare(other Version) int {
	for _, pair := range [3][2]int{
		{v.Major, other.Major},
		{v.Minor, other.Minor},
		{v.Patch, other.Patch},
	} {
		switch {
		case pair[0] < pair[1]:
			return -1
		case pair[0] > pair[1]:
			return 1
		}
	}
	return 0
}

// ParseVersion parses a MAJOR.MINOR.PATCH version, tolerating a leading "v".
func ParseVersion(s string) (Version, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("invalid version %q: expected MAJOR.MINOR.PATCH", s)
	}

	var v Version
	targets := [3]*int{&v.Major, &v.Minor, &v.Patch}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return Version{}, fmt.Errorf("invalid version %q: %w", s, err)
		}
		if n < 0 {
			return Version{}, fmt.Errorf("invalid version %q: negative component", s)
		}
		*targets[i] = n
	}
	return v, nil
}

// CompareVersions parses both versions and compares them.
func CompareVersions(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

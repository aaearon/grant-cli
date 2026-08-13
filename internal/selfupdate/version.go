package selfupdate

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a Semantic Versioning 2.0.0 version.
//
// GoReleaser normally emits plain MAJOR.MINOR.PATCH tags, but it can also
// produce pre-release (`1.2.3-rc.1`) and build-metadata (`1.2.3+build.5`)
// tags, and grant must be able to update from such a build. Ordering follows
// SemVer precedence: build metadata is ignored, and a pre-release sorts
// before its corresponding release.
type Version struct {
	Major int
	Minor int
	Patch int
	// Prerelease is the dot-separated pre-release string without the leading
	// "-" (empty when the version is a normal release).
	Prerelease string
	// Build is the build metadata without the leading "+". It never affects
	// ordering.
	Build string
}

// String renders the version without a leading "v".
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// Compare returns -1 if v < other, 0 if they have equal precedence, and 1 if
// v > other. Build metadata is ignored, per SemVer 2.0.0 §10.
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
	return comparePrerelease(v.Prerelease, other.Prerelease)
}

// comparePrerelease implements SemVer 2.0.0 §11.3-11.4.
func comparePrerelease(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "": // a release outranks any pre-release of the same core version
		return 1
	case b == "":
		return -1
	}

	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		if c := comparePrereleaseIdentifier(aParts[i], bParts[i]); c != 0 {
			return c
		}
	}

	// All shared identifiers are equal: the larger set has higher precedence.
	switch {
	case len(aParts) < len(bParts):
		return -1
	case len(aParts) > len(bParts):
		return 1
	}
	return 0
}

// comparePrereleaseIdentifier compares one dot-separated pre-release
// identifier. Numeric identifiers compare numerically and always rank lower
// than alphanumeric ones, which compare in ASCII order.
func comparePrereleaseIdentifier(a, b string) int {
	aNum, aIsNum := parseNumericIdentifier(a)
	bNum, bIsNum := parseNumericIdentifier(b)

	switch {
	case aIsNum && bIsNum:
		switch {
		case aNum < bNum:
			return -1
		case aNum > bNum:
			return 1
		}
		return 0
	case aIsNum:
		return -1
	case bIsNum:
		return 1
	}
	return strings.Compare(a, b)
}

// parseNumericIdentifier reports whether s is a numeric identifier and, if so,
// its value.
func parseNumericIdentifier(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	if !isAllDigits(s) {
		return 0, false
	}
	return n, true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hasLeadingZero reports whether a numeric identifier violates SemVer's
// no-leading-zeroes rule.
func hasLeadingZero(s string) bool {
	return len(s) > 1 && s[0] == '0'
}

// isValidIdentifierChars reports whether s consists only of SemVer's allowed
// identifier characters: [0-9A-Za-z-].
func isValidIdentifierChars(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9',
			r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r == '-':
		default:
			return false
		}
	}
	return true
}

// ParseVersion parses a SemVer 2.0.0 version. A leading "v" or "V" is
// tolerated, since Git tags conventionally carry one and GitHub reports the
// tag verbatim.
func ParseVersion(s string) (Version, error) {
	rest := strings.TrimSpace(s)
	if rest != "" && (rest[0] == 'v' || rest[0] == 'V') {
		rest = rest[1:]
	}

	var v Version

	// Split off build metadata first: it may itself contain "-".
	if idx := strings.IndexByte(rest, '+'); idx >= 0 {
		v.Build = rest[idx+1:]
		rest = rest[:idx]
		if err := validateDotSeparated(v.Build, "build metadata", false); err != nil {
			return Version{}, fmt.Errorf("invalid version %q: %w", s, err)
		}
	}

	// Then the pre-release, which starts at the first "-" after the core.
	if idx := strings.IndexByte(rest, '-'); idx >= 0 {
		v.Prerelease = rest[idx+1:]
		rest = rest[:idx]
		if err := validateDotSeparated(v.Prerelease, "pre-release", true); err != nil {
			return Version{}, fmt.Errorf("invalid version %q: %w", s, err)
		}
	}

	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("invalid version %q: expected MAJOR.MINOR.PATCH", s)
	}

	targets := [3]*int{&v.Major, &v.Minor, &v.Patch}
	for i, part := range parts {
		if !isAllDigits(part) {
			return Version{}, fmt.Errorf("invalid version %q: %q is not a non-negative integer", s, part)
		}
		if hasLeadingZero(part) {
			return Version{}, fmt.Errorf("invalid version %q: %q has a leading zero", s, part)
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return Version{}, fmt.Errorf("invalid version %q: %w", s, err)
		}
		*targets[i] = n
	}
	return v, nil
}

// validateDotSeparated validates a pre-release or build-metadata string.
// Numeric pre-release identifiers may not carry leading zeroes; build
// metadata identifiers may.
func validateDotSeparated(s, what string, checkLeadingZero bool) error {
	if s == "" {
		return fmt.Errorf("empty %s", what)
	}
	for _, ident := range strings.Split(s, ".") {
		if ident == "" {
			return fmt.Errorf("empty identifier in %s", what)
		}
		if !isValidIdentifierChars(ident) {
			return fmt.Errorf("illegal character in %s identifier %q", what, ident)
		}
		if checkLeadingZero && isAllDigits(ident) && hasLeadingZero(ident) {
			return fmt.Errorf("numeric %s identifier %q has a leading zero", what, ident)
		}
	}
	return nil
}

// CompareVersions parses both versions and compares them by SemVer precedence.
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

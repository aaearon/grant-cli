package selfupdate

import (
	"math"
	"strconv"
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Version
		wantErr bool
	}{
		{name: "plain", input: "1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3}},
		{name: "lowercase v prefix", input: "v1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3}},
		{name: "uppercase V prefix", input: "V1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3}},
		{name: "zeroes", input: "0.0.0", want: Version{}},
		{name: "double digit", input: "1.10.0", want: Version{Major: 1, Minor: 10}},
		{name: "surrounding whitespace", input: "  1.2.3 ", want: Version{Major: 1, Minor: 2, Patch: 3}},

		// Pre-release and build metadata: GoReleaser can emit both, and a
		// pre-release build must still be able to update.
		{name: "prerelease rc", input: "1.2.3-rc.1", want: Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc.1"}},
		{name: "prerelease without dot", input: "1.2.3-rc1", want: Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc1"}},
		{name: "prerelease with hyphen", input: "1.2.3-alpha-beta", want: Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "alpha-beta"}},
		{name: "prerelease with v prefix", input: "v0.8.0-next.2", want: Version{Minor: 8, Prerelease: "next.2"}},
		{name: "build metadata", input: "1.2.3+build.5", want: Version{Major: 1, Minor: 2, Patch: 3, Build: "build.5"}},
		{name: "build metadata with leading zero allowed", input: "1.2.3+001", want: Version{Major: 1, Minor: 2, Patch: 3, Build: "001"}},
		{name: "prerelease and build", input: "1.2.3-rc.1+sha.abc123", want: Version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc.1", Build: "sha.abc123"}},
		{name: "build metadata containing hyphen", input: "1.2.3+build-5", want: Version{Major: 1, Minor: 2, Patch: 3, Build: "build-5"}},

		{name: "empty", input: "", wantErr: true},
		{name: "too few parts", input: "1.2", wantErr: true},
		{name: "too many parts", input: "1.2.3.4", wantErr: true},
		{name: "non numeric", input: "1.x.3", wantErr: true},
		{name: "negative", input: "1.-2.3", wantErr: true},
		{name: "just v", input: "v", wantErr: true},
		{name: "leading zero in core", input: "01.2.3", wantErr: true},
		{name: "leading zero in patch", input: "1.2.03", wantErr: true},
		{name: "empty prerelease", input: "1.2.3-", wantErr: true},
		{name: "empty prerelease identifier", input: "1.2.3-rc..1", wantErr: true},
		{name: "leading zero in numeric prerelease", input: "1.2.3-01", wantErr: true},
		{name: "illegal prerelease character", input: "1.2.3-rc_1", wantErr: true},
		{name: "empty build metadata", input: "1.2.3+", wantErr: true},
		{name: "illegal build character", input: "1.2.3+build_5", wantErr: true},
		{name: "plus signed core", input: "1.+2.3", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %+v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseVersion(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseVersionRejectsOverflow(t *testing.T) {
	// A component larger than int64 must be rejected, not silently wrapped.
	huge := strconv.FormatUint(math.MaxUint64, 10) + "0"
	if v, err := ParseVersion(huge + ".0.0"); err == nil {
		t.Errorf("expected overflow error, got %+v", v)
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		name string
		v    Version
		want string
	}{
		{name: "release", v: Version{Major: 1, Minor: 10, Patch: 2}, want: "1.10.2"},
		{name: "prerelease", v: Version{Major: 1, Prerelease: "rc.1"}, want: "1.0.0-rc.1"},
		{name: "build", v: Version{Major: 1, Build: "sha.abc"}, want: "1.0.0+sha.abc"},
		{name: "both", v: Version{Major: 1, Prerelease: "rc.1", Build: "sha.abc"}, want: "1.0.0-rc.1+sha.abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionStringRoundTrips(t *testing.T) {
	inputs := []string{"1.2.3", "1.2.3-rc.1", "1.2.3+build.5", "1.2.3-rc.1+build.5", "0.0.0"}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			v, err := ParseVersion(in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := v.String(); got != in {
				t.Errorf("round trip: %q -> %q", in, got)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name    string
		a, b    string
		want    int
		wantErr bool
	}{
		{name: "patch less", a: "1.0.0", b: "1.0.1", want: -1},
		{name: "v prefix equal", a: "v1.2.3", b: "1.2.3", want: 0},
		{name: "minor numeric not lexical", a: "1.10.0", b: "1.9.0", want: 1},
		{name: "equal", a: "1.0.0", b: "1.0.0", want: 0},
		{name: "major greater", a: "2.0.0", b: "1.99.99", want: 1},
		{name: "major less", a: "0.9.0", b: "1.0.0", want: -1},

		// SemVer 2.0.0 precedence rules.
		{name: "prerelease sorts before release", a: "1.0.0-rc.1", b: "1.0.0", want: -1},
		{name: "release sorts after prerelease", a: "1.0.0", b: "1.0.0-rc.1", want: 1},
		{name: "numeric prerelease compares numerically", a: "1.0.0-rc.2", b: "1.0.0-rc.10", want: -1},
		{name: "numeric identifier below alphanumeric", a: "1.0.0-1", b: "1.0.0-alpha", want: -1},
		{name: "alpha before beta", a: "1.0.0-alpha", b: "1.0.0-beta", want: -1},
		{name: "larger identifier set wins", a: "1.0.0-alpha", b: "1.0.0-alpha.1", want: -1},
		{name: "equal prereleases", a: "1.0.0-rc.1", b: "1.0.0-rc.1", want: 0},
		{name: "build metadata ignored", a: "1.0.0+build.1", b: "1.0.0+build.9", want: 0},
		{name: "build metadata ignored against bare", a: "1.0.0+build.1", b: "1.0.0", want: 0},
		{name: "prerelease upgrade to release of same core", a: "0.8.0-rc.1", b: "0.8.0", want: -1},
		{name: "prerelease of newer core beats release", a: "0.9.0-rc.1", b: "0.8.0", want: 1},

		{name: "invalid a", a: "nope", b: "1.0.0", wantErr: true},
		{name: "invalid b", a: "1.0.0", b: "nope", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareVersions(tt.a, tt.b)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

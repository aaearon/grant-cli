package selfupdate

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Version
		wantErr bool
	}{
		{name: "plain", input: "1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3}},
		{name: "v prefix", input: "v1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3}},
		{name: "zeroes", input: "0.0.0", want: Version{}},
		{name: "double digit", input: "1.10.0", want: Version{Major: 1, Minor: 10}},
		{name: "empty", input: "", wantErr: true},
		{name: "too few parts", input: "1.2", wantErr: true},
		{name: "too many parts", input: "1.2.3.4", wantErr: true},
		{name: "non numeric", input: "1.x.3", wantErr: true},
		{name: "negative", input: "1.-2.3", wantErr: true},
		{name: "prerelease unsupported", input: "1.2.3-rc1", wantErr: true},
		{name: "just v", input: "v", wantErr: true},
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

func TestVersionString(t *testing.T) {
	v := Version{Major: 1, Minor: 10, Patch: 2}
	if got := v.String(); got != "1.10.2" {
		t.Errorf("String() = %q, want %q", got, "1.10.2")
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

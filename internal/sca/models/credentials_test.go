package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAWSCredentials_JSONUnmarshal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		jsonInput        string
		wantAccessKeyID  string
		wantSecretKey    string
		wantSessionToken string
	}{
		{
			name: "valid credentials from API response",
			jsonInput: `{
				"aws_access_key": "ASIAXXXXXXXXXEXAMPLE",
				"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"aws_session_token": "FwoGZXIvYXdzEBYaDHqa0AP+SESSION+TOKEN+EXAMPLE"
			}`,
			wantAccessKeyID:  "ASIAXXXXXXXXXEXAMPLE",
			wantSecretKey:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantSessionToken: "FwoGZXIvYXdzEBYaDHqa0AP+SESSION+TOKEN+EXAMPLE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var creds AWSCredentials
			if err := json.Unmarshal([]byte(tt.jsonInput), &creds); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}

			if creds.AccessKeyID != tt.wantAccessKeyID {
				t.Errorf("AccessKeyID = %q, want %q", creds.AccessKeyID, tt.wantAccessKeyID)
			}
			if creds.SecretAccessKey != tt.wantSecretKey {
				t.Errorf("SecretAccessKey = %q, want %q", creds.SecretAccessKey, tt.wantSecretKey)
			}
			if creds.SessionToken != tt.wantSessionToken {
				t.Errorf("SessionToken = %q, want %q", creds.SessionToken, tt.wantSessionToken)
			}
		})
	}
}

func TestParseAWSCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantErr bool
		// Asserted only when wantErr is true and non-empty. Without it the
		// empty-string guard is inert: json.Unmarshal rejects "" anyway, so
		// deleting the guard changes only the message.
		wantErrContains string
		// Asserted only when wantErr is false. Without these the parser could
		// swap SecretAccessKey and SessionToken and this package would not
		// notice — it discarded the parsed value entirely.
		wantAccessKeyID  string
		wantSecretKey    string
		wantSessionToken string
	}{
		{
			name: "valid JSON string",
			// Distinguishable values: a swap of any two must change the result.
			input:            `{"aws_access_key":"AKIAVALUE","aws_secret_access_key":"SECRETVALUE","aws_session_token":"TOKENVALUE"}`,
			wantErr:          false,
			wantAccessKeyID:  "AKIAVALUE",
			wantSecretKey:    "SECRETVALUE",
			wantSessionToken: "TOKENVALUE",
		},
		{
			name:            "empty string",
			input:           "",
			wantErr:         true,
			wantErrContains: "empty credentials string",
		},
		{
			name:    "malformed JSON",
			input:   `{not json}`,
			wantErr: true,
		},
		{
			name:    "empty credential fields",
			input:   `{"aws_access_key":"","aws_secret_access_key":"","aws_session_token":""}`,
			wantErr: true,
		},
		{
			name:    "partial credential fields - missing session token",
			input:   `{"aws_access_key":"AKIA","aws_secret_access_key":"secret","aws_session_token":""}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			creds, err := ParseAWSCredentials(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseAWSCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("error = %v, want it to contain %q", err, tt.wantErrContains)
				}
				return
			}
			if creds.AccessKeyID != tt.wantAccessKeyID {
				t.Errorf("AccessKeyID = %q, want %q", creds.AccessKeyID, tt.wantAccessKeyID)
			}
			if creds.SecretAccessKey != tt.wantSecretKey {
				t.Errorf("SecretAccessKey = %q, want %q", creds.SecretAccessKey, tt.wantSecretKey)
			}
			if creds.SessionToken != tt.wantSessionToken {
				t.Errorf("SessionToken = %q, want %q", creds.SessionToken, tt.wantSessionToken)
			}
		})
	}
}

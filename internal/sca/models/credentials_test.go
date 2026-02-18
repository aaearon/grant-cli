package models

import (
	"encoding/json"
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
	}{
		{
			name:    "valid JSON string",
			input:   `{"aws_access_key":"AKIA","aws_secret_access_key":"secret","aws_session_token":"token"}`,
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			input:   `{not json}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseAWSCredentials(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAWSCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

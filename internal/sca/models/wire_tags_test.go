package models

import (
	"encoding/json"
	"testing"
)

// TestElevateRequest_JSONTags pins the request-body field names. The existing
// marshal tests decode into the same Go struct, so a renamed tag round-trips
// trivially; these assert the literal keys the API sees.
func TestElevateRequest_JSONTags(t *testing.T) {
	t.Parallel()

	req := ElevateRequest{
		CSP:            CSPAzure,
		OrganizationID: "org-tag-1",
		Targets: []ElevateTarget{
			{WorkspaceID: "ws-tag-2", RoleID: "role-tag-3", RoleName: "Role Tag Four"},
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"csp", "organizationId", "targets"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("request body is missing key %q: %s", key, b)
		}
	}

	var targets []map[string]json.RawMessage
	if err := json.Unmarshal(raw["targets"], &targets); err != nil {
		t.Fatalf("unmarshal targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets len = %d, want 1", len(targets))
	}
	for _, key := range []string{"workspaceId", "roleId", "roleName"} {
		if _, ok := targets[0][key]; !ok {
			t.Errorf("target is missing key %q: %s", key, b)
		}
	}
}

// TestElevateResponse_DecodesPopulatedAccessCredentials is the guard for the
// single field `grant env` exists to deliver. Every prior test only ever saw
// "accessCredentials": null, or marshaled a Go struct whose field was nil, so
// renaming the tag passed the entire repo suite while every AWS elevation
// silently returned no credentials.
func TestElevateResponse_DecodesPopulatedAccessCredentials(t *testing.T) {
	t.Parallel()

	// Distinguishable values so a swap in the parser cannot be masked.
	const wire = `{
	  "response": {
	    "csp": "AWS",
	    "organizationId": "org-creds-1",
	    "results": [
	      {
	        "workspaceId": "111122223333",
	        "roleId": "arn:aws:iam::111122223333:role/Admin",
	        "sessionId": "sess-creds-2",
	        "accessCredentials": "{\"aws_access_key\":\"ACCESSKEYVALUE\",\"aws_secret_access_key\":\"SECRETKEYVALUE\",\"aws_session_token\":\"SESSIONTOKENVALUE\"}",
	        "errorInfo": null
	      }
	    ]
	  }
	}`

	var resp ElevateResponse
	if err := json.Unmarshal([]byte(wire), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Response.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(resp.Response.Results))
	}
	raw := resp.Response.Results[0].AccessCredentials
	if raw == nil {
		t.Fatal("accessCredentials did not decode: got nil, want the populated credentials string")
	}

	creds, err := ParseAWSCredentials(*raw)
	if err != nil {
		t.Fatalf("ParseAWSCredentials: %v", err)
	}
	if creds.AccessKeyID != "ACCESSKEYVALUE" {
		t.Errorf("AccessKeyID = %q, want %q", creds.AccessKeyID, "ACCESSKEYVALUE")
	}
	if creds.SecretAccessKey != "SECRETKEYVALUE" {
		t.Errorf("SecretAccessKey = %q, want %q", creds.SecretAccessKey, "SECRETKEYVALUE")
	}
	if creds.SessionToken != "SESSIONTOKENVALUE" {
		t.Errorf("SessionToken = %q, want %q", creds.SessionToken, "SESSIONTOKENVALUE")
	}
}

// TestElevateResponse_AccessCredentialsAbsentOrEmpty covers the non-populated
// shapes of the same field.
func TestElevateResponse_AccessCredentialsAbsentOrEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		result       string
		wantNil      bool
		wantParseErr bool
	}{
		{name: "explicit null", result: `{"accessCredentials": null}`, wantNil: true},
		{name: "absent", result: `{"sessionId": "sess-1"}`, wantNil: true},
		{name: "empty string", result: `{"accessCredentials": ""}`, wantParseErr: true},
		{name: "malformed inner JSON", result: `{"accessCredentials": "{not json}"}`, wantParseErr: true},
		{name: "incomplete inner JSON", result: `{"accessCredentials": "{\"aws_access_key\":\"AK\"}"}`, wantParseErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var res ElevateTargetResult
			if err := json.Unmarshal([]byte(tt.result), &res); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if tt.wantNil {
				if res.AccessCredentials != nil {
					t.Fatalf("accessCredentials = %q, want nil", *res.AccessCredentials)
				}
				return
			}
			if res.AccessCredentials == nil {
				t.Fatal("accessCredentials = nil, want a decoded string")
			}
			_, err := ParseAWSCredentials(*res.AccessCredentials)
			if (err != nil) != tt.wantParseErr {
				t.Errorf("ParseAWSCredentials error = %v, wantErr %v", err, tt.wantParseErr)
			}
		})
	}
}

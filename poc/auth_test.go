package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseStartAuthResponse_PasswordChallenge(t *testing.T) {
	resp := startAuthResponse{
		Success: true,
		Result: startAuthResult{
			SessionID: "sess-123",
			Challenges: []challenge{
				{Mechanisms: []mechanism{
					{Name: "UP", MechanismID: "mech-up-1", PromptMechChosen: "Enter password"},
				}},
				{Mechanisms: []mechanism{
					{Name: "OATH", MechanismID: "mech-oath-1", PromptMechChosen: "Enter OATH code"},
				}},
			},
		},
	}

	if !resp.Success {
		t.Fatal("expected Success=true")
	}
	if resp.Result.SessionID != "sess-123" {
		t.Errorf("expected SessionID=sess-123, got %s", resp.Result.SessionID)
	}
	if len(resp.Result.Challenges) != 2 {
		t.Fatalf("expected 2 challenges, got %d", len(resp.Result.Challenges))
	}
	if resp.Result.Challenges[0].Mechanisms[0].Name != "UP" {
		t.Errorf("expected first mechanism=UP, got %s", resp.Result.Challenges[0].Mechanisms[0].Name)
	}
	if resp.Result.Challenges[1].Mechanisms[0].Name != "OATH" {
		t.Errorf("expected second mechanism=OATH, got %s", resp.Result.Challenges[1].Mechanisms[0].Name)
	}
}

func TestParseAdvanceAuthResponse_LoginSuccess(t *testing.T) {
	body := `{
		"Success": true,
		"Result": {
			"Summary": "LoginSuccess",
			"Token": "jwt-token-here",
			"TokenLifetime": 3600
		}
	}`
	var resp advanceAuthResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected Success=true")
	}
	if resp.Result.Summary != "LoginSuccess" {
		t.Errorf("expected Summary=LoginSuccess, got %s", resp.Result.Summary)
	}
	if resp.Result.Token != "jwt-token-here" {
		t.Errorf("expected token, got %s", resp.Result.Token)
	}
}

func TestParseAdvanceAuthMidResponse_StartOOB(t *testing.T) {
	body := `{
		"Success": true,
		"Result": {
			"Summary": "OobVerification"
		}
	}`
	var resp advanceAuthMidResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected Success=true")
	}
	if resp.Result.Summary != "OobVerification" {
		t.Errorf("expected Summary=OobVerification, got %s", resp.Result.Summary)
	}
}

func TestFindMechanism(t *testing.T) {
	challenges := []challenge{
		{Mechanisms: []mechanism{
			{Name: "UP", MechanismID: "mech-up-1"},
		}},
		{Mechanisms: []mechanism{
			{Name: "OATH", MechanismID: "mech-oath-1"},
			{Name: "OTP", MechanismID: "mech-otp-1"},
		}},
	}

	// Find UP in challenge 0
	m, err := findMechanism(challenges[0], "UP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.MechanismID != "mech-up-1" {
		t.Errorf("expected mech-up-1, got %s", m.MechanismID)
	}

	// Find OATH in challenge 1
	m, err = findMechanism(challenges[1], "OATH")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.MechanismID != "mech-oath-1" {
		t.Errorf("expected mech-oath-1, got %s", m.MechanismID)
	}

	// Missing mechanism
	_, err = findMechanism(challenges[0], "OATH")
	if err == nil {
		t.Fatal("expected error for missing mechanism")
	}
}

func TestAuthenticate_FullFlow(t *testing.T) {
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/Security/StartAuthentication":
			json.NewEncoder(w).Encode(startAuthResponse{
				Success: true,
				Result: startAuthResult{
					SessionID: "test-session",
					Challenges: []challenge{
						{Mechanisms: []mechanism{
							{Name: "UP", MechanismID: "mech-up", PromptMechChosen: "password"},
						}},
						{Mechanisms: []mechanism{
							{Name: "OATH", MechanismID: "mech-oath", PromptMechChosen: "oath code"},
						}},
					},
				},
			})
		case "/Security/AdvanceAuthentication":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			action := body["Action"].(string)

			switch action {
			case "Answer":
				mechID := body["MechanismId"].(string)
				if mechID == "mech-up" {
					// Password step -> return mid-response (NewPackage)
					json.NewEncoder(w).Encode(advanceAuthMidResponse{
						baseResponse: baseResponse{Success: true},
						Result:       advanceAuthMidResult{Summary: "NewPackage"},
					})
				} else if mechID == "mech-oath" {
					// OATH step -> return login success
					json.NewEncoder(w).Encode(advanceAuthResponse{
						baseResponse: baseResponse{Success: true},
						Result: advanceAuthResult{
							Summary:       "LoginSuccess",
							Token:         "test-jwt-token",
							TokenLifetime: 3600,
						},
					})
				}
			case "StartOOB":
				json.NewEncoder(w).Encode(advanceAuthMidResponse{
					baseResponse: baseResponse{Success: true},
					Result:       advanceAuthMidResult{Summary: "OobVerification"},
				})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := server.Client()
	token, cookies, err := authenticate(client, server.URL, "testuser", "testpass", "123456")
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if token != "test-jwt-token" {
		t.Errorf("expected test-jwt-token, got %s", token)
	}
	if cookies == nil {
		t.Error("expected non-nil cookies")
	}
	// StartAuth + AdvanceAuth(password) + AdvanceAuth(StartOOB) + AdvanceAuth(OATH answer) = 4 calls
	if callCount != 4 {
		t.Errorf("expected 4 HTTP calls, got %d", callCount)
	}
}

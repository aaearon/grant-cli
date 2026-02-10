package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
)

// --- Request/response models matching CyberArk Identity API ---

type baseResponse struct {
	Success   bool   `json:"Success"`
	Exception string `json:"Exception"`
	Message   string `json:"Message"`
}

type mechanism struct {
	Name             string `json:"Name"`
	MechanismID      string `json:"MechanismId"`
	PromptMechChosen string `json:"PromptMechChosen"`
}

type challenge struct {
	Mechanisms []mechanism `json:"Mechanisms"`
}

type startAuthResult struct {
	SessionID  string      `json:"SessionId"`
	Challenges []challenge `json:"Challenges"`
	TenantID   string      `json:"TenantId"`
}

type startAuthResponse struct {
	Success bool            `json:"Success"`
	Message string          `json:"Message"`
	Result  startAuthResult `json:"Result"`
}

type advanceAuthResult struct {
	Summary       string `json:"Summary"`
	Token         string `json:"Token"`
	RefreshToken  string `json:"RefreshToken"`
	TokenLifetime int    `json:"TokenLifetime"`
	Auth          string `json:"Auth"`
	CustomerID    string `json:"CustomerID"`
	UserID        string `json:"UserId"`
	PodFqdn       string `json:"PodFqdn"`
}

type advanceAuthResponse struct {
	baseResponse
	Result advanceAuthResult `json:"Result"`
}

type advanceAuthMidResult struct {
	Summary string `json:"Summary"`
}

type advanceAuthMidResponse struct {
	baseResponse
	Result advanceAuthMidResult `json:"Result"`
}

// findMechanism finds a mechanism by name (case-insensitive) in a challenge.
func findMechanism(c challenge, name string) (*mechanism, error) {
	target := strings.ToUpper(name)
	for i := range c.Mechanisms {
		if strings.ToUpper(c.Mechanisms[i].Name) == target {
			return &c.Mechanisms[i], nil
		}
	}
	return nil, fmt.Errorf("mechanism %q not found in challenge", name)
}

// postJSON sends a JSON POST request and returns the raw response body.
func postJSON(client *http.Client, url string, payload interface{}) ([]byte, http.Header, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal error: %w", err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IDAP-NATIVE-CLIENT", "true")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, resp.Header, nil
}

// authenticate performs the full CyberArk Identity auth flow:
// StartAuthentication -> AdvanceAuthentication(password) -> AdvanceAuthentication(StartOOB for OATH) -> AdvanceAuthentication(TOTP code)
// Returns the JWT token and the client's cookie jar.
func authenticate(client *http.Client, identityURL, username, password, totpCode string) (string, http.CookieJar, error) {
	if client.Jar == nil {
		jar, _ := cookiejar.New(nil)
		client.Jar = jar
	}

	// Step 1: StartAuthentication
	startBody, _, err := postJSON(client, identityURL+"/Security/StartAuthentication", map[string]interface{}{
		"User":                  username,
		"Version":               "1.0",
		"PlatformTokenResponse": true,
		"AssociatedEntityType":  "API",
		"MfaRequestor":          "DeviceAgent",
	})
	if err != nil {
		return "", nil, fmt.Errorf("StartAuthentication failed: %w", err)
	}

	var startResp startAuthResponse
	if err := json.Unmarshal(startBody, &startResp); err != nil {
		return "", nil, fmt.Errorf("parse StartAuthentication: %w", err)
	}
	if !startResp.Success {
		return "", nil, fmt.Errorf("StartAuthentication not successful: %s", startResp.Message)
	}
	if len(startResp.Result.Challenges) == 0 {
		return "", nil, fmt.Errorf("no challenges returned from StartAuthentication")
	}

	fmt.Printf("[auth] SessionID: %s\n", startResp.Result.SessionID)
	fmt.Printf("[auth] Challenges: %d\n", len(startResp.Result.Challenges))
	for i, c := range startResp.Result.Challenges {
		for _, m := range c.Mechanisms {
			fmt.Printf("[auth]   Challenge[%d]: %s (id=%s)\n", i, m.Name, m.MechanismID)
		}
	}

	sessionID := startResp.Result.SessionID

	// Step 2: AdvanceAuthentication with password (UP mechanism)
	upMech, err := findMechanism(startResp.Result.Challenges[0], "UP")
	if err != nil {
		return "", nil, fmt.Errorf("no UP mechanism in first challenge: %w", err)
	}

	fmt.Printf("[auth] Advancing with password (mechanismId=%s)...\n", upMech.MechanismID)
	advBody, _, err := postJSON(client, identityURL+"/Security/AdvanceAuthentication", map[string]interface{}{
		"SessionId":   sessionID,
		"MechanismId": upMech.MechanismID,
		"Action":      "Answer",
		"Answer":      password,
	})
	if err != nil {
		return "", nil, fmt.Errorf("AdvanceAuthentication(password) failed: %w", err)
	}

	// Check if password alone completed auth (single-challenge case)
	var midResp advanceAuthMidResponse
	if err := json.Unmarshal(advBody, &midResp); err != nil {
		return "", nil, fmt.Errorf("parse AdvanceAuthentication(password): %w", err)
	}

	// If the response is already LoginSuccess (password-only, no MFA)
	if midResp.Result.Summary == "LoginSuccess" {
		var finalResp advanceAuthResponse
		if err := json.Unmarshal(advBody, &finalResp); err != nil {
			return "", nil, fmt.Errorf("parse LoginSuccess response: %w", err)
		}
		return finalResp.Result.Token, client.Jar, nil
	}

	if !midResp.Success {
		return "", nil, fmt.Errorf("AdvanceAuthentication(password) failed: %s", midResp.Message)
	}
	fmt.Printf("[auth] Password accepted, summary: %s\n", midResp.Result.Summary)

	// Step 3: Find OATH mechanism in second challenge and StartOOB
	if len(startResp.Result.Challenges) < 2 {
		return "", nil, fmt.Errorf("expected at least 2 challenges for MFA, got %d", len(startResp.Result.Challenges))
	}

	oathMech, err := findMechanism(startResp.Result.Challenges[1], "OATH")
	if err != nil {
		return "", nil, fmt.Errorf("no OATH mechanism in second challenge: %w", err)
	}

	fmt.Printf("[auth] Starting OOB for OATH (mechanismId=%s)...\n", oathMech.MechanismID)
	_, _, err = postJSON(client, identityURL+"/Security/AdvanceAuthentication", map[string]interface{}{
		"SessionId":   sessionID,
		"MechanismId": oathMech.MechanismID,
		"Action":      "StartOOB",
	})
	if err != nil {
		return "", nil, fmt.Errorf("AdvanceAuthentication(StartOOB) failed: %w", err)
	}

	// Step 4: AdvanceAuthentication with TOTP code
	fmt.Printf("[auth] Submitting TOTP code...\n")
	finalBody, _, err := postJSON(client, identityURL+"/Security/AdvanceAuthentication", map[string]interface{}{
		"SessionId":   sessionID,
		"MechanismId": oathMech.MechanismID,
		"Action":      "Answer",
		"Answer":      totpCode,
	})
	if err != nil {
		return "", nil, fmt.Errorf("AdvanceAuthentication(TOTP) failed: %w", err)
	}

	// Parse as mid-response first to check Summary
	var totpMidResp advanceAuthMidResponse
	if err := json.Unmarshal(finalBody, &totpMidResp); err != nil {
		return "", nil, fmt.Errorf("parse AdvanceAuthentication(TOTP): %w", err)
	}

	if totpMidResp.Result.Summary == "LoginSuccess" {
		var finalResp advanceAuthResponse
		if err := json.Unmarshal(finalBody, &finalResp); err != nil {
			return "", nil, fmt.Errorf("parse LoginSuccess response: %w", err)
		}
		fmt.Printf("[auth] Login successful! Token length: %d\n", len(finalResp.Result.Token))
		return finalResp.Result.Token, client.Jar, nil
	}

	return "", nil, fmt.Errorf("unexpected summary after TOTP: %s (body: %s)", totpMidResp.Result.Summary, string(finalBody))
}

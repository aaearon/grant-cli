package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

func main() {
	// Load .env from parent directory (project root)
	if err := godotenv.Load("../.env"); err != nil {
		// Try current directory as fallback
		if err := godotenv.Load(".env"); err != nil {
			log.Println("Warning: no .env file found, using environment variables")
		}
	}

	username := os.Getenv("SCA_USERNAME")
	password := os.Getenv("SCA_PASSWORD")
	totpSecret := os.Getenv("SCA_TOTP_SECRET")
	identityURL := os.Getenv("SCA_IDENTITY_URL")

	if username == "" || password == "" || totpSecret == "" || identityURL == "" {
		log.Fatal("Missing required env vars: SCA_USERNAME, SCA_PASSWORD, SCA_TOTP_SECRET, SCA_IDENTITY_URL")
	}

	fmt.Println("=== SCA Access API PoC ===")
	fmt.Printf("Identity URL: %s\n", identityURL)
	fmt.Printf("Username:     %s\n", username)

	// Generate TOTP code
	totpCode, err := generateTOTP(totpSecret)
	if err != nil {
		log.Fatalf("TOTP generation failed: %v", err)
	}
	fmt.Printf("TOTP code:    %s\n\n", totpCode)

	// Create HTTP client with cookie jar
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	// Step 1: Authenticate
	fmt.Println("--- Step 1: Authenticate ---")
	token, _, err := authenticate(client, identityURL, username, password, totpCode)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	fmt.Printf("\nJWT token (first 80 chars): %s...\n", token[:min(80, len(token))])

	// Decode JWT claims (unverified) to inspect subdomain / platform_domain
	fmt.Println("\n--- JWT Claims ---")
	printJWTClaims(token)

	// Extract subdomain from identity URL for building service URLs
	// Identity URL format: https://abz4452.id.cyberark.cloud
	// The subdomain is "abz4452"
	subdomain := extractSubdomain(identityURL)
	fmt.Printf("\nTenant subdomain: %s\n", subdomain)

	// Step 2: Try SCA Access API endpoints with different service name patterns
	// The ISP URL pattern is: https://{subdomain}{separator}{serviceName}.{platformDomain}
	// Known: IdsecSCAService uses "sca" with "." separator -> abz4452.sca.cyberark.cloud
	serviceNames := []struct {
		name      string
		separator string
		desc      string
	}{
		{"sca", ".", "SDK pattern (abz4452.sca.cyberark.cloud)"},
		{"", "", "No service (abz4452.cyberark.cloud)"},
		{"access", ".", "Access service (abz4452.access.cyberark.cloud)"},
		{"sca", "-", "Dash separator (abz4452-sca.cyberark.cloud)"},
	}

	platformDomain := extractPlatformDomain(identityURL, subdomain)
	fmt.Printf("Platform domain: %s\n\n", platformDomain)

	for _, svc := range serviceNames {
		var baseURL string
		if svc.name != "" {
			baseURL = fmt.Sprintf("https://%s%s%s.%s", subdomain, svc.separator, svc.name, platformDomain)
		} else {
			baseURL = fmt.Sprintf("https://%s.%s", subdomain, platformDomain)
		}
		fmt.Printf("--- Trying: %s ---\n", svc.desc)
		fmt.Printf("    Base URL: %s\n", baseURL)
		tryAccessAPIs(client, baseURL, token)
		fmt.Println()
	}

	// Step 3: Try /token/{app_id} endpoint
	fmt.Println("--- Step 3: /token endpoint ---")
	for _, svc := range serviceNames {
		var baseURL string
		if svc.name != "" {
			baseURL = fmt.Sprintf("https://%s%s%s.%s", subdomain, svc.separator, svc.name, platformDomain)
		} else {
			baseURL = fmt.Sprintf("https://%s.%s", subdomain, platformDomain)
		}
		tryTokenEndpoint(client, baseURL, token)
	}
}

// tryAccessAPIs calls the SCA Access API endpoints and logs responses.
func tryAccessAPIs(client *http.Client, baseURL, token string) {
	// Q3 & Q4: GET /access/csp/eligibility
	fmt.Println("  [GET] /access/csp/eligibility")
	doRequest(client, "GET", baseURL+"/access/csp/eligibility", token, nil)

	// Q1: POST /access/elevate (we'll try with empty body first to see what it expects)
	fmt.Println("  [POST] /access/elevate")
	doRequest(client, "POST", baseURL+"/access/elevate", token, map[string]interface{}{})
}

// tryTokenEndpoint calls /token/{app_id} to check if it requires pre-registration.
func tryTokenEndpoint(client *http.Client, baseURL, token string) {
	// Q2: POST /token/{app_id}
	fmt.Printf("  [POST] %s/token/test-app\n", baseURL)
	doRequest(client, "POST", baseURL+"/token/test-app", token, map[string]interface{}{})
}

// doRequest executes an HTTP request with Bearer token and logs the response.
func doRequest(client *http.Client, method, url, token string, body interface{}) {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		fmt.Printf("    ERROR creating request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("    ERROR: %v\n", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("    Status: %d\n", resp.StatusCode)

	// Try to pretty-print JSON
	var prettyJSON json.RawMessage
	if json.Unmarshal(respBody, &prettyJSON) == nil {
		formatted, err := json.MarshalIndent(prettyJSON, "    ", "  ")
		if err == nil {
			fmt.Printf("    Body: %s\n", string(formatted))
			return
		}
	}
	// Fallback: print first 500 chars
	bodyStr := string(respBody)
	if len(bodyStr) > 500 {
		bodyStr = bodyStr[:500] + "..."
	}
	fmt.Printf("    Body: %s\n", bodyStr)
}

// printJWTClaims decodes and prints JWT claims without verification.
func printJWTClaims(token string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		fmt.Println("  Invalid JWT format")
		return
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("  Failed to decode JWT payload: %v\n", err)
		return
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		fmt.Printf("  Failed to parse JWT claims: %v\n", err)
		return
	}

	formatted, _ := json.MarshalIndent(claims, "  ", "  ")
	fmt.Printf("  %s\n", string(formatted))
}

// extractSubdomain extracts the tenant subdomain from an Identity URL.
// e.g., "https://abz4452.id.cyberark.cloud" -> "abz4452"
func extractSubdomain(identityURL string) string {
	url := strings.TrimPrefix(identityURL, "https://")
	url = strings.TrimPrefix(url, "http://")
	return strings.Split(url, ".")[0]
}

// extractPlatformDomain extracts the platform domain from the Identity URL,
// removing the ".id" prefix. e.g., "abz4452.id.cyberark.cloud" -> "cyberark.cloud"
func extractPlatformDomain(identityURL, subdomain string) string {
	url := strings.TrimPrefix(identityURL, "https://")
	url = strings.TrimPrefix(url, "http://")
	// Remove subdomain prefix
	url = strings.TrimPrefix(url, subdomain+".")
	// Remove "id." prefix if present
	url = strings.TrimPrefix(url, "id.")
	return url
}

package models

import (
	"encoding/json"
	"fmt"
)

// AWSCredentials contains temporary AWS credentials returned by SCA elevation.
type AWSCredentials struct {
	AccessKeyID     string `json:"aws_access_key"`
	SecretAccessKey string `json:"aws_secret_access_key"`
	SessionToken    string `json:"aws_session_token"`
}

// ParseAWSCredentials parses an accessCredentials JSON string into AWSCredentials.
func ParseAWSCredentials(s string) (*AWSCredentials, error) {
	if s == "" {
		return nil, fmt.Errorf("empty credentials string")
	}
	var creds AWSCredentials
	if err := json.Unmarshal([]byte(s), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse AWS credentials: %w", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		return nil, fmt.Errorf("incomplete AWS credentials: missing required fields")
	}
	return &creds, nil
}

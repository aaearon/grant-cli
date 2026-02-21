package models

import (
	"encoding/json"
	"errors"
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
		return nil, errors.New("empty credentials string")
	}
	var creds AWSCredentials
	if err := json.Unmarshal([]byte(s), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse AWS credentials: %w", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		return nil, errors.New("incomplete AWS credentials: missing required fields")
	}
	return &creds, nil
}

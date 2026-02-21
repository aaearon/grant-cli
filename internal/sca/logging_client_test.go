package sca

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

type mockLogger struct {
	calls []logCall
}

type logCall struct {
	level string
	msg   string
}

func (m *mockLogger) Info(msg string, v ...interface{}) {
	m.calls = append(m.calls, logCall{level: "info", msg: fmt.Sprintf(msg, v...)})
}

func (m *mockLogger) Error(msg string, v ...interface{}) {
	m.calls = append(m.calls, logCall{level: "error", msg: fmt.Sprintf(msg, v...)})
}

func (m *mockLogger) Debug(msg string, v ...interface{}) {
	m.calls = append(m.calls, logCall{level: "debug", msg: fmt.Sprintf(msg, v...)})
}

func TestLoggingClient_Get(t *testing.T) {
	tests := []struct {
		name       string
		route      string
		resp       *http.Response
		err        error
		wantLevel  string
		wantSubstr string
	}{
		{
			name:       "success logs method route and status",
			route:      "/api/access/AZURE/eligibility",
			resp:       &http.Response{StatusCode: 200, Header: http.Header{}},
			err:        nil,
			wantLevel:  "info",
			wantSubstr: "GET /api/access/AZURE/eligibility -> 200",
		},
		{
			name:       "error logs method route and error",
			route:      "/api/access/AZURE/eligibility",
			resp:       nil,
			err:        errors.New("connection refused"),
			wantLevel:  "error",
			wantSubstr: "GET /api/access/AZURE/eligibility failed: connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ml := &mockLogger{}
			inner := &mockHTTPClient{getResponse: tt.resp, getError: tt.err}
			lc := newLoggingClient(inner, ml)

			resp, err := lc.Get(t.Context(), tt.route, nil)

			if tt.err != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if resp.StatusCode != tt.resp.StatusCode {
					t.Errorf("expected status %d, got %d", tt.resp.StatusCode, resp.StatusCode)
				}
			}

			found := false
			for _, c := range ml.calls {
				if c.level == tt.wantLevel && strings.Contains(c.msg, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s log containing %q, got calls: %v", tt.wantLevel, tt.wantSubstr, ml.calls)
			}
		})
	}
}

func TestLoggingClient_Post(t *testing.T) {
	tests := []struct {
		name       string
		route      string
		resp       *http.Response
		err        error
		wantLevel  string
		wantSubstr string
	}{
		{
			name:       "success logs method route and status",
			route:      "/api/access/elevate",
			resp:       &http.Response{StatusCode: 200, Header: http.Header{}},
			err:        nil,
			wantLevel:  "info",
			wantSubstr: "POST /api/access/elevate -> 200",
		},
		{
			name:       "error logs method route and error",
			route:      "/api/access/elevate",
			resp:       nil,
			err:        errors.New("timeout"),
			wantLevel:  "error",
			wantSubstr: "POST /api/access/elevate failed: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ml := &mockLogger{}
			inner := &mockHTTPClient{postResponse: tt.resp, postError: tt.err}
			lc := newLoggingClient(inner, ml)

			resp, err := lc.Post(t.Context(), tt.route, nil)

			if tt.err != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if resp.StatusCode != tt.resp.StatusCode {
					t.Errorf("expected status %d, got %d", tt.resp.StatusCode, resp.StatusCode)
				}
			}

			found := false
			for _, c := range ml.calls {
				if c.level == tt.wantLevel && strings.Contains(c.msg, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s log containing %q, got calls: %v", tt.wantLevel, tt.wantSubstr, ml.calls)
			}
		})
	}
}

func TestLoggingClient_LogsDuration(t *testing.T) {
	ml := &mockLogger{}
	inner := &mockHTTPClient{
		getResponse: &http.Response{StatusCode: 200, Header: http.Header{}},
	}
	lc := newLoggingClient(inner, ml)

	_, _ = lc.Get(t.Context(), "/api/test", nil)

	found := false
	for _, c := range ml.calls {
		if c.level == "info" && strings.Contains(c.msg, "ms)") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected info log containing duration in ms, got calls: %v", ml.calls)
	}
}

func TestLoggingClient_DebugLogsHeaders(t *testing.T) {
	ml := &mockLogger{}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "Bearer eyJhbGci.secret.token")
	inner := &mockHTTPClient{
		getResponse: &http.Response{StatusCode: 200, Header: h},
	}
	lc := newLoggingClient(inner, ml)

	_, _ = lc.Get(t.Context(), "/api/test", nil)

	var debugCall *logCall
	for i, c := range ml.calls {
		if c.level == "debug" {
			debugCall = &ml.calls[i]
			break
		}
	}
	if debugCall == nil {
		t.Fatal("expected debug log for response headers")
	}
	if strings.Contains(debugCall.msg, "eyJhbGci") {
		t.Error("expected Authorization header to be redacted, but found token value")
	}
	if !strings.Contains(debugCall.msg, "[REDACTED]") {
		t.Error("expected [REDACTED] in debug log for Authorization header")
	}
	if !strings.Contains(debugCall.msg, "application/json") {
		t.Error("expected Content-Type header in debug log")
	}
}

func TestRedactHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		wantHas  string
		wantNot  string
	}{
		{
			name: "redacts Authorization",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer eyJtoken123")
				return h
			}(),
			wantHas: "Bearer [REDACTED]",
			wantNot: "eyJtoken123",
		},
		{
			name: "preserves other headers",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Content-Type", "application/json")
				h.Set("X-API-Version", "2.0")
				return h
			}(),
			wantHas: "application/json",
			wantNot: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactHeaders(tt.headers)
			str := fmt.Sprintf("%v", result)

			if tt.wantHas != "" && !strings.Contains(str, tt.wantHas) {
				t.Errorf("expected %q in result %q", tt.wantHas, str)
			}
			if tt.wantNot != "" && strings.Contains(str, tt.wantNot) {
				t.Errorf("did not expect %q in result %q", tt.wantNot, str)
			}
		})
	}
}

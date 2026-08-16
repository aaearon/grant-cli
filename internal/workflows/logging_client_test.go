package workflows

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// This file mirrors internal/sca/logging_client_test.go. The two logging
// clients are byte-identical, but this one had no test at all while sitting on
// the live path — NewAccessRequestService wraps every UAR request in it.

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

func (m *mockLogger) has(level, substr string) bool {
	for _, c := range m.calls {
		if c.level == level && strings.Contains(c.msg, substr) {
			return true
		}
	}
	return false
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
			route:      "/api/workflows/requests",
			resp:       &http.Response{StatusCode: 200, Header: http.Header{}},
			wantLevel:  "info",
			wantSubstr: "GET /api/workflows/requests -> 200",
		},
		{
			name:       "error logs method route and error",
			route:      "/api/workflows/requests",
			err:        errors.New("connection refused"),
			wantLevel:  "error",
			wantSubstr: "GET /api/workflows/requests failed: connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ml := &mockLogger{}
			inner := &mockHTTPClient{getResponses: []*http.Response{tt.resp}, getError: tt.err}
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

			if !ml.has(tt.wantLevel, tt.wantSubstr) {
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
			route:      "/api/workflows/requests",
			resp:       &http.Response{StatusCode: 200, Header: http.Header{}},
			wantLevel:  "info",
			wantSubstr: "POST /api/workflows/requests -> 200",
		},
		{
			name:       "error logs method route and error",
			route:      "/api/workflows/requests",
			err:        errors.New("timeout"),
			wantLevel:  "error",
			wantSubstr: "POST /api/workflows/requests failed: timeout",
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

			if !ml.has(tt.wantLevel, tt.wantSubstr) {
				t.Errorf("expected %s log containing %q, got calls: %v", tt.wantLevel, tt.wantSubstr, ml.calls)
			}
		})
	}
}

// TestLoggingClient_GetUsesGet and its Post twin pin the verb dispatch: routing
// Get through inner.Post would otherwise be invisible.
func TestLoggingClient_GetUsesGet(t *testing.T) {
	var gotGet, gotPost bool
	inner := &mockHTTPClient{
		getFn: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
			gotGet = true
			return &http.Response{StatusCode: 200, Header: http.Header{}}, nil
		},
		postFn: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
			gotPost = true
			return &http.Response{StatusCode: 200, Header: http.Header{}}, nil
		},
	}
	lc := newLoggingClient(inner, &mockLogger{})

	if _, err := lc.Get(t.Context(), "/api/workflows/requests", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !gotGet {
		t.Error("loggingClient.Get did not call inner.Get")
	}
	if gotPost {
		t.Error("loggingClient.Get called inner.Post")
	}
}

func TestLoggingClient_PostUsesPost(t *testing.T) {
	var gotGet, gotPost bool
	inner := &mockHTTPClient{
		getFn: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
			gotGet = true
			return &http.Response{StatusCode: 200, Header: http.Header{}}, nil
		},
		postFn: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
			gotPost = true
			return &http.Response{StatusCode: 200, Header: http.Header{}}, nil
		},
	}
	lc := newLoggingClient(inner, &mockLogger{})

	if _, err := lc.Post(t.Context(), "/api/workflows/requests", nil); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if !gotPost {
		t.Error("loggingClient.Post did not call inner.Post")
	}
	if gotGet {
		t.Error("loggingClient.Post called inner.Get")
	}
}

// TestLoggingClient_PropagatesInnerError guards against the decorator
// swallowing the inner error and manufacturing a success.
func TestLoggingClient_PropagatesInnerError(t *testing.T) {
	sentinel := errors.New("inner transport failure")

	t.Run("get", func(t *testing.T) {
		lc := newLoggingClient(&mockHTTPClient{getError: sentinel}, &mockLogger{})
		resp, err := lc.Get(t.Context(), "/api/workflows/requests", nil)
		if !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the inner error", err)
		}
		if resp != nil {
			t.Errorf("response = %#v, want nil on error", resp)
		}
	})

	t.Run("post", func(t *testing.T) {
		lc := newLoggingClient(&mockHTTPClient{postError: sentinel}, &mockLogger{})
		resp, err := lc.Post(t.Context(), "/api/workflows/requests", nil)
		if !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the inner error", err)
		}
		if resp != nil {
			t.Errorf("response = %#v, want nil on error", resp)
		}
	})
}

func TestLoggingClient_LogsDuration(t *testing.T) {
	ml := &mockLogger{}
	inner := &mockHTTPClient{getResponses: []*http.Response{{StatusCode: 200, Header: http.Header{}}}}
	lc := newLoggingClient(inner, ml)

	_, _ = lc.Get(t.Context(), "/api/workflows/requests", nil)

	if !ml.has("info", "ms)") {
		t.Errorf("expected info log containing duration in ms, got calls: %v", ml.calls)
	}
}

// TestLoggingClient_DebugLogsHeaders is the token-leak guard: response headers
// go to the debug log verbatim except Authorization, which must be redacted.
func TestLoggingClient_DebugLogsHeaders(t *testing.T) {
	ml := &mockLogger{}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "Bearer eyJhbGci.secret.token")
	inner := &mockHTTPClient{getResponses: []*http.Response{{StatusCode: 200, Header: h}}}
	lc := newLoggingClient(inner, ml)

	_, _ = lc.Get(t.Context(), "/api/workflows/requests", nil)

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
		name    string
		headers http.Header
		wantHas string
		wantNot string
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
				return h
			}(),
			wantHas: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := fmt.Sprintf("%v", redactHeaders(tt.headers))

			if tt.wantHas != "" && !strings.Contains(str, tt.wantHas) {
				t.Errorf("expected %q in result %q", tt.wantHas, str)
			}
			if tt.wantNot != "" && strings.Contains(str, tt.wantNot) {
				t.Errorf("did not expect %q in result %q", tt.wantNot, str)
			}
		})
	}
}

package cmd

import (
	"fmt"
	"testing"
)

// spyLogger captures Info() calls for testing verbose output.
type spyLogger struct {
	messages []string
}

func (s *spyLogger) Info(msg string, v ...interface{}) {
	s.messages = append(s.messages, fmt.Sprintf(msg, v...))
}

func TestCmdLogger_DefaultIsNotNil(t *testing.T) {
	if log == nil {
		t.Fatal("package-level log should not be nil")
	}
}

func TestCmdLogger_SpyCaptures(t *testing.T) {
	spy := &spyLogger{}
	oldLog := log
	log = spy
	defer func() { log = oldLog }()

	log.Info("hello %s", "world")

	if len(spy.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(spy.messages))
	}
	if spy.messages[0] != "hello world" {
		t.Errorf("expected %q, got %q", "hello world", spy.messages[0])
	}
}

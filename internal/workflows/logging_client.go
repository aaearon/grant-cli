package workflows

import (
	"context"
	"net/http"
	"time"
)

type logger interface {
	Info(msg string, v ...interface{})
	Error(msg string, v ...interface{})
	Debug(msg string, v ...interface{})
}

type loggingClient struct {
	inner  httpClient
	logger logger
}

func newLoggingClient(inner httpClient, l logger) *loggingClient {
	return &loggingClient{inner: inner, logger: l}
}

func (c *loggingClient) Get(ctx context.Context, route string, params interface{}) (*http.Response, error) {
	return c.do("GET", route, func() (*http.Response, error) {
		return c.inner.Get(ctx, route, params)
	})
}

func (c *loggingClient) Post(ctx context.Context, route string, body interface{}) (*http.Response, error) {
	return c.do("POST", route, func() (*http.Response, error) {
		return c.inner.Post(ctx, route, body)
	})
}

func (c *loggingClient) do(method, route string, fn func() (*http.Response, error)) (*http.Response, error) {
	c.logger.Info("%s %s", method, route)
	start := time.Now()

	resp, err := fn()
	elapsed := time.Since(start)

	if err != nil {
		c.logger.Error("%s %s failed: %v", method, route, err)
		return nil, err
	}

	c.logger.Info("%s %s -> %d (%dms)", method, route, resp.StatusCode, elapsed.Milliseconds())
	if resp.Header != nil {
		c.logger.Debug("Response headers: %v", redactHeaders(resp.Header))
	}

	return resp, nil
}

func redactHeaders(h http.Header) http.Header {
	redacted := h.Clone()
	if redacted.Get("Authorization") != "" {
		redacted.Set("Authorization", "Bearer [REDACTED]")
	}
	return redacted
}

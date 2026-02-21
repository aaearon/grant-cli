BINARY_NAME := grant
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w \
	-X github.com/aaearon/grant-cli/cmd.version=$(VERSION) \
	-X github.com/aaearon/grant-cli/cmd.commit=$(COMMIT) \
	-X github.com/aaearon/grant-cli/cmd.buildDate=$(DATE)

.PHONY: build test test-race test-integration test-all test-coverage lint clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

test:
	go test ./... -v

test-race:
	go test -race ./... -v

test-integration:
	go test ./cmd -tags=integration -v

test-all: test-race test-integration

test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY_NAME) coverage.out
	go clean

BINARY_NAME := sca-cli
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w \
	-X github.com/aaearon/sca-cli/cmd.version=$(VERSION) \
	-X github.com/aaearon/sca-cli/cmd.commit=$(COMMIT) \
	-X github.com/aaearon/sca-cli/cmd.buildDate=$(DATE)

.PHONY: build test lint clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

test:
	go test ./... -v

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY_NAME)
	go clean

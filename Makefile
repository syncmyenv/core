BIN     := bin/syncmyenv
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X github.com/syncmyenv/core/internal/cli.version=$(VERSION) -X github.com/syncmyenv/core/internal/cli.commit=$(COMMIT)

.PHONY: build test lint tidy run clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/syncmyenv
	ln -sf syncmyenv bin/sme

test:
	go test -race ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

tidy:
	go mod tidy

run: build
	./$(BIN) $(ARGS)

clean:
	rm -rf bin dist

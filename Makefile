.PHONY: all build run run-mock test test-race bench lint clean docker-build docker-up docker-down

BINARY_DIR := bin
RELAYHOOK_BIN := $(BINARY_DIR)/relayhook
MOCK_BIN := $(BINARY_DIR)/mock-receiver

all: build

build:
	@mkdir -p $(BINARY_DIR)
	@echo "==> Building RelayHook..."
	go build -ldflags="-s -w" -o $(RELAYHOOK_BIN) ./cmd/relayhook
	@echo "==> Building Mock-Receiver..."
	go build -ldflags="-s -w" -o $(MOCK_BIN) ./cmd/mock-receiver
	@echo "==> Build complete: $(RELAYHOOK_BIN), $(MOCK_BIN)"

run:
	go run ./cmd/relayhook -port 8080 -workers 8

run-mock:
	go run ./cmd/mock-receiver -port 9090 -fail-first 2 -secret whsec_demo_secret

test:
	go test -v ./...

test-race:
	go test -race -v ./...

bench:
	go test -bench=BenchmarkIngestEvent -benchmem -run=^$$ ./internal/handler

lint:
	go vet ./...

clean:
	rm -rf $(BINARY_DIR) *.db *.db-journal *.db-wal

docker-build:
	docker build -t relayhook:latest .

docker-up:
	docker compose up -d

docker-down:
	docker compose down -v

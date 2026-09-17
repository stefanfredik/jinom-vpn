# Variables
APP_NAME := jinom-vpn
BIN_DIR := bin
BINARY := $(BIN_DIR)/$(APP_NAME)
MAIN_FILE := cmd/server/main.go

# Colors
CYAN := \033[0;36m
RESET := \033[0m

.PHONY: all build run test test-race vet clean dev help setup install-logrotate

all: build

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build         Build the binary"
	@echo "  run           Run the application as root"
	@echo "  test          Run tests"
	@echo "  clean         Remove binary and build artifacts"
	@echo "  dev           Run the application as root with hot reload (requires air)"
	@echo "  test-race     Run tests with the race detector"
	@echo "  vet           Run go vet"
	@echo "  setup         Setup the VPN infrastructure on the host (requires root)"
	@echo "  install-logrotate  Install log rotation for the PPP hook log (requires root)"

build:
	@echo "$(CYAN)Building $(APP_NAME)...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@go build -o $(BINARY) $(MAIN_FILE)

run: build
	@echo "$(CYAN)Running $(APP_NAME) as root...$(RESET)"
	@sudo ./$(BINARY)

test:
	@echo "$(CYAN)Running tests...$(RESET)"
	@go test -v ./...

test-race:
	@echo "$(CYAN)Running tests with race detector...$(RESET)"
	@go test -race ./...

vet:
	@echo "$(CYAN)Running go vet...$(RESET)"
	@go vet ./...

clean:
	@echo "$(CYAN)Cleaning build artifacts...$(RESET)"
	@rm -rf $(BIN_DIR)

dev:
	@if command -v air > /dev/null; then \
		sudo air; \
	else \
		echo "$(CYAN)air is not installed. Running with sudo go run...$(RESET)"; \
		sudo go run $(MAIN_FILE); \
	fi

setup:
	@echo "$(CYAN)Setting up VPN infrastructure...$(RESET)"
	@sudo ./scripts/setup-vpn-infra.sh

install-logrotate:
	@echo "$(CYAN)Installing logrotate config...$(RESET)"
	@sudo install -m 0644 deploy/jinom-vpn-ppp.logrotate /etc/logrotate.d/jinom-vpn-ppp

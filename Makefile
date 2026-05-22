# Variables
APP_NAME := jinom-vpn
BIN_DIR := bin
BINARY := $(BIN_DIR)/$(APP_NAME)
MAIN_FILE := cmd/server/main.go

# Colors
CYAN := \033[0;36m
RESET := \033[0m

.PHONY: all build run test clean dev help

all: build

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build         Build the binary"
	@echo "  run           Run the application"
	@echo "  test          Run tests"
	@echo "  clean         Remove binary and build artifacts"
	@echo "  dev           Run the application with hot reload (requires air)"

build:
	@echo "$(CYAN)Building $(APP_NAME)...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@go build -o $(BINARY) $(MAIN_FILE)

run: build
	@echo "$(CYAN)Running $(APP_NAME)...$(RESET)"
	@./$(BINARY)

test:
	@echo "$(CYAN)Running tests...$(RESET)"
	@go test -v ./...

clean:
	@echo "$(CYAN)Cleaning build artifacts...$(RESET)"
	@rm -rf $(BIN_DIR)

dev:
	@if command -v air > /dev/null; then \
		air; \
	else \
		echo "$(CYAN)air is not installed. Running with go run...$(RESET)"; \
		go run $(MAIN_FILE); \
	fi

# Variables
APP_NAME := jinom-vpn
BIN_DIR := bin
BINARY := $(BIN_DIR)/$(APP_NAME)
MAIN_FILE := cmd/server/main.go
ENV_FILE := .env

# Colors
CYAN := \033[0;36m
RESET := \033[0m

.PHONY: all build run test clean dev help docker-build docker-up docker-down

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
	@echo "  docker-build  Build docker image"
	@echo "  docker-up     Run the application in docker"
	@echo "  docker-down   Stop docker container"

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
	}

docker-build:
	@echo "$(CYAN)Building Docker image...$(RESET)"
	@docker build -t $(APP_NAME) .

docker-up:
	@if [ ! -f $(ENV_FILE) ]; then \
		echo "$(CYAN)Creating .env from .env.example...$(RESET)"; \
		cp .env.example .env; \
	fi
	@echo "$(CYAN)Running in Docker...$(RESET)"
	@docker run --rm -it --env-file $(ENV_FILE) -p 8090:8090 $(APP_NAME)

docker-down:
	@echo "$(CYAN)Stopping Docker containers...$(RESET)"
	@docker stop $$(docker ps -q --filter ancestor=$(APP_NAME)) 2>/dev/null || true

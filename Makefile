GO ?= go
COMPOSE ?= docker compose
OAPI_CODEGEN_VERSION := v2.8.2
SQLC_VERSION := v1.31.1

.DEFAULT_GOAL := build
.PHONY: generate build run migrate-up migrate-down up down fmt vet test

generate:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) -config api/oapi-codegen.yaml api/openapi.yaml
	$(GO) run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate -f sqlc.yaml

build:
	$(GO) build -trimpath -o bin/server ./cmd/server
	$(GO) build -trimpath -o bin/migrate ./cmd/migrate

run:
	$(GO) run ./cmd/server

migrate-up:
	$(GO) run ./cmd/migrate up

migrate-down:
	$(GO) run ./cmd/migrate down

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

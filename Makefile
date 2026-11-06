GO ?= go
COMPOSE ?= docker compose
OAPI_CODEGEN_VERSION := v2.8.2
SQLC_VERSION := v1.31.1

.DEFAULT_GOAL := build
.PHONY: generate build run migrate-up migrate-down up down fmt vet test test-integration test-db-up test-db-down

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

# По умолчанию используется одноразовая БД из compose.test.yaml.
test-integration:
	TEST_DATABASE_URL="$${TEST_DATABASE_URL:-postgres://test:test@127.0.0.1:15432/threats_test?sslmode=disable}" $(GO) test -count=1 -tags=integration ./internal/storage/postgres/...

test-db-up:
	$(COMPOSE) -f compose.test.yaml up -d --wait

test-db-down:
	$(COMPOSE) -f compose.test.yaml down

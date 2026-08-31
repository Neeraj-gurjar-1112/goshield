# GoShield backend tasks.
#
# On Windows the default Go temp dir can be blocked by Application Control
# policy, so test binaries are built inside the repo instead.
export GOTMPDIR ?= $(CURDIR)/.gotmp

DATABASE_URL ?= postgres://goshield:goshield@localhost:5432/goshield?sslmode=disable
MIGRATIONS_DIR := migrations

.PHONY: run build test test-race test-docker lint tidy swagger migrate-up migrate-down

run:
	go run ./cmd/server

build:
	go build -o bin/server ./cmd/server

test:
	@mkdir -p "$(GOTMPDIR)"
	go test ./...

# Requires cgo and a C toolchain (gcc / mingw-w64 on Windows).
test-race:
	@mkdir -p "$(GOTMPDIR)"
	CGO_ENABLED=1 go test -race ./...

# Windows Smart App Control blocks some locally built test binaries, and the
# race detector needs a C toolchain. Running the suite in a Linux container
# sidesteps both.
test-docker:
	docker run --rm -v "$(CURDIR):/app" -v goshield_gomod:/go/pkg/mod -w /app golang:1.25 go test -race ./...

# Regenerate the swagger spec from the handler annotations.
swagger:
	swag init -g cmd/server/main.go -o docs --parseDependency --parseInternal

# Same, without needing swag installed on the host.
swagger-docker:
	docker run --rm -v "$(CURDIR):/app" -v goshield_gomod:/go/pkg/mod -w /app golang:1.25 \n		sh -c "go install github.com/swaggo/swag/cmd/swag@v1.16.6 && swag init -g cmd/server/main.go -o docs --parseDependency --parseInternal"

lint:
	go vet ./...
	gofmt -l .

tidy:
	go mod tidy

migrate-up:
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

# Rooster — frontend (web/, Vue + Vite) & backend (Rust workspace)

CARGO ?= cargo
NPM   ?= npm

BIN_NAME    := rooster
BIN_PATH    := target/release/$(BIN_NAME)
WEB_DIR     := web
DIST_DIR    := $(WEB_DIR)/dist

.PHONY: help all backend frontend build run dev test check clean fmt lint

help:
	@echo "Backend (Rust):"
	@echo "  make build        - Release build (backend binary in target/release/)"
	@echo "  make run          - Build and run the rooster binary (release)"
	@echo "  make test         - Run cargo tests"
	@echo "  make check        - cargo check + clippy"
	@echo "  make fmt          - cargo fmt"
	@echo ""
	@echo "Frontend (web/):"
	@echo "  make frontend     - Production build (vue-tsc + vite build)"
	@echo "  make dev          - Vite dev server"
	@echo ""
	@echo "Combined:"
	@echo "  make all          - Backend + frontend release builds"
	@echo "  make clean        - Remove target/ and web/dist/"

all: backend frontend

# ---------- Backend ----------

backend:
	$(CARGO) build --release

run: backend
	$(BIN_PATH)

test:
	$(CARGO) test --workspace

check:
	$(CARGO) check --workspace
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

# ---------- Frontend ----------

frontend:
	$(NPM) --prefix $(WEB_DIR) run build

dev:
	$(NPM) --prefix $(WEB_DIR) run dev

# ---------- Cleanup ----------

clean:
	$(CARGO) clean
	rm -rf $(DIST_DIR)

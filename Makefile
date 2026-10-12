.PHONY: test test-wasm benchmark wasm wasm-component wasm_exec

BUILD_VERSION=$(or ${VERSION}, dev)

generate:
	cd ./__generator__/ && go generate .

test: generate
	go test ./...

check:
	cd ./cmd/documentation-checker && go run .

linux_amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-linux-amd64 ./cmd/falco
	cd ./dist/ && cp ./falco-linux-amd64 ./falco && tar cfz falco-linux-amd64.tar.gz ./falco

linux_arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-linux-arm64 ./cmd/falco
	cd ./dist/ && cp ./falco-linux-arm64 ./falco && tar cfz falco-linux-arm64.tar.gz ./falco

darwin_amd64:
	GOOS=darwin GOARCH=amd64 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-darwin-amd64 ./cmd/falco
	cd ./dist/ && cp ./falco-darwin-amd64 ./falco && tar cfz falco-darwin-amd64.tar.gz ./falco

darwin_arm64:
	GOOS=darwin GOARCH=arm64 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-darwin-arm64 ./cmd/falco
	cd ./dist/ && cp ./falco-darwin-arm64 ./falco && tar cfz falco-darwin-arm64.tar.gz ./falco

all: linux_amd64 linux_arm64 darwin_amd64 darwin_arm64

lint:
	golangci-lint run

modernize:
	go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -test ./...

local: test lint modernize

clean:
	rm ./dist/falco-*

plugin_ci:
	cd ./examples/plugin/lint_backend_name && \
		go build -o falco-backend-name . && \
		cp ./falco-backend-name /usr/local/bin/falco-backend-name

benchmark:
	cd cmd/benchmark && go test -bench . -benchmem

wasm:
	@mkdir -p wasm
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o wasm/falco.wasm ./cmd/wasm

# wasm-component builds the WASI Component Model ("reactor") artifact:
# wasm/falco-component.wasm, exporting lint/format/parse/tokenize at the world
# root per wit/falco.wit. Consume it from any wasmtime embedding
# (Rust/Python/Ruby/.NET/C) or, for JS, via `jco transpile`. See
# docs/wasm-component.md and cmd/falco-component/hosts/ for host smoke tests.
#
# Requires `wasm-tools` (cargo install wasm-tools / brew install wasm-tools) and
# the preview1 reactor adapter (auto-downloaded to $(WASI_ADAPTER) if missing).
#
# The adapter is cached at a version-keyed path so bumping WASI_ADAPTER_VERSION
# invalidates a stale download, and it is verified against a pinned SHA-256
# after a --fail download into a temp file -- so a 404/5xx error page, a
# truncated transfer, or a tampered artifact can never poison the cache or get
# embedded into the component. Update WASI_ADAPTER_SHA256 whenever you bump the
# version.
WASI_ADAPTER_VERSION ?= v46.0.0
WASI_ADAPTER_SHA256 ?= 447b27d25221a12afd2c0732f7c150833aad9a2af42ae36ccff9270f4c7559bf
WASI_ADAPTER ?= wasm/wasi_snapshot_preview1.reactor-$(WASI_ADAPTER_VERSION).wasm
WASI_ADAPTER_URL := https://github.com/bytecodealliance/wasmtime/releases/download/$(WASI_ADAPTER_VERSION)/wasi_snapshot_preview1.reactor.wasm

# Minimum wasm-tools major version. `wasm-tools component embed/new/validate`
# flags and the emitted component encoding vary across releases, so the build
# asserts at least this major to stay reproducible across machines.
WASM_TOOLS_MIN_MAJOR ?= 1

wasm-component:
	@mkdir -p wasm
	@command -v wasm-tools >/dev/null 2>&1 || { echo "error: wasm-tools not found (cargo install wasm-tools / brew install wasm-tools)"; exit 1; }
	@wt_ver=$$(wasm-tools --version | awk '{print $$2}'); \
		wt_major=$${wt_ver%%.*}; \
		if [ -z "$$wt_major" ] || [ "$$wt_major" -lt "$(WASM_TOOLS_MIN_MAJOR)" ] 2>/dev/null; then \
			echo "error: wasm-tools $$wt_ver is too old; need >= $(WASM_TOOLS_MIN_MAJOR).0.0 (the component embed/new flags used here vary across versions)"; exit 1; \
		fi
	@test -f "$(WASI_ADAPTER)" || { \
		echo "downloading WASI adapter $(WASI_ADAPTER_VERSION)..."; \
		curl --fail -sSL -o "$(WASI_ADAPTER).tmp" "$(WASI_ADAPTER_URL)" || { rm -f "$(WASI_ADAPTER).tmp"; echo "error: failed to download $(WASI_ADAPTER_URL)"; exit 1; }; \
		if command -v shasum >/dev/null 2>&1; then sum=$$(shasum -a 256 "$(WASI_ADAPTER).tmp" | cut -d' ' -f1); \
		elif command -v sha256sum >/dev/null 2>&1; then sum=$$(sha256sum "$(WASI_ADAPTER).tmp" | cut -d' ' -f1); \
		else rm -f "$(WASI_ADAPTER).tmp"; echo "error: no shasum/sha256sum found to verify adapter"; exit 1; fi; \
		if [ "$$sum" != "$(WASI_ADAPTER_SHA256)" ]; then rm -f "$(WASI_ADAPTER).tmp"; echo "error: adapter checksum mismatch: got $$sum want $(WASI_ADAPTER_SHA256)"; exit 1; fi; \
		mv "$(WASI_ADAPTER).tmp" "$(WASI_ADAPTER)"; \
	}
	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -ldflags="-s -w" -o wasm/falco-core.wasm ./cmd/falco-component
	wasm-tools component embed wit --world falco wasm/falco-core.wasm -o wasm/falco-embedded.wasm
	wasm-tools component new wasm/falco-embedded.wasm --adapt wasi_snapshot_preview1="$(WASI_ADAPTER)" -o wasm/falco-component.wasm
	wasm-tools validate --features component-model wasm/falco-component.wasm
	@rm -f wasm/falco-core.wasm wasm/falco-embedded.wasm
	@echo "built wasm/falco-component.wasm"

# test-wasm runs the wasip1/wasm-tagged unit tests for cmd/falco-component
# (including the canonical-ABI allocator/alignment and
# return-area encoding guards in abi_test.go) under wasmtime. Those files carry
# `//go:build wasip1 && wasm`, so the default `make test` (host `go test ./...`)
# cannot build them; this target is the only place they execute. Requires
# wasmtime on PATH.
test-wasm:
	@command -v wasmtime >/dev/null 2>&1 || { echo "error: wasmtime not found (brew install wasmtime)"; exit 1; }
	GOOS=wasip1 GOARCH=wasm go test -exec "$$(go env GOROOT)/lib/wasm/go_wasip1_wasm_exec" ./cmd/falco-component/...

wasm_exec:
	@mkdir -p wasm
	cp "$$(find "$$(go env GOROOT)" -name 'wasm_exec.js' 2>/dev/null | head -1)" wasm/

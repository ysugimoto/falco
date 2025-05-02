.PHONY: test benchmark

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
	go build ./cmd/falco

clean:
	rm ./dist/falco-*

plugin_ci:
	cd ./examples/plugin/lint_backend_name && \
		go build -o falco-backend-name . && \
		cp ./falco-backend-name /usr/local/bin/falco-backend-name

benchmark:
	cd cmd/benchmark && go test -bench . -benchmem

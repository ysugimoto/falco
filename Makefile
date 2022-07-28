.PHONY: test

BUILD_VERSION=$(or ${VERSION}, dev)

generate:
	cd ./__generator__/ && go generate .

test: generate
	go test ./...

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-linux-amd64 ./cmd/falco

darwin_amd64:
	GOOS=darwin GOARCH=amd64 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-darwin-amd64 ./cmd/falco

darwin_arm64:
	GOOS=darwin GOARCH=arm64 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-darwin-arm64 ./cmd/falco

all: linux darwin_amd64 darwin_arm64

lint:
	golangci-lint run

local: test lint
	go build ./cmd/falco

clean:
	rm ./dist/falco-*

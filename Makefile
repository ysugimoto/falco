.PHONY: test

BUILD_VERSION=$(or ${VERSION}, dev)

generate:
	cd ./__generator__/ && go generate .

test: generate
	go list ./... | xargs go test

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-linux-amd64 ./cmd/falco

darwin:
	GOOS=darwin GOARCH=amd64 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-darwin-amd64 ./cmd/falco
	GOOS=darwin GOARCH=arm64 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-darwin-arm64 ./cmd/falco

lint:
	golangci-lint run

local: test lint
	go build ./cmd/falco

all: linux darwin

clean:
	rm ./dist/falco-*

.PHONY: test

BUILD_VERSION=$(or ${VERSION}, dev)

generate:
	cd ./__generator__/ && go generate .

test: generate
	go list ./... | xargs go test

linux:
	GOOS=linux GOARCH=amd64 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-linux-amd64 cli/*.go

darwin:
	GOOS=darwin GOARCH=amd64 go build \
			 -ldflags "-X main.version=$(BUILD_VERSION)" \
			 -o dist/falco-darwin-amd64 cli/*.go

lint:
	golangci-lint run

local: test lint
	go build -o falco cli/*.go

all: linux darwin

clean:
	rm ./dist/falco-*

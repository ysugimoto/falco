.PHONY: test

generate:
	cd ./__generator__/ && go generate .

test: generate
	go list ./... | xargs go test

linux: test
	GOOS=linux GOARCH=amd64 go build -o dist/falco-linux-amd64 cli/*.go
	GOOS=linux GOARCH=arm64 go build -o dist/falco-linux-arm64 cli/*.go

darwin: test
	GOOS=darwin GOARCH=amd64 go build -o dist/falco-darwin-amd64 cli/*.go
	GOOS=darwin GOARCH=arm64 go build -o dist/falco-darwin-arm64 cli/*.go

all: linux darwin

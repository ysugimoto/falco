.PHONY: test

generate:
	cd ./__generator__/ && go generate .

test: generate
	go list ./... | xargs go test

linux: test
	GOOS=linux GOARCH=amd64 go build -o dist/falco-linux-amd64 cli/*.go

darwin: test
	GOOS=darwin GOARCH=amd64 go build -o dist/falco-darwin-amd64 cli/*.go

all: linux darwin

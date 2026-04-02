VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build build-osx build-linux test clean docker-image

build: build-osx build-linux

build-osx:
	@mkdir -p build
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o build/tsidp-server-darwin-arm64-$(shell date +%Y-%m-%d)-$(shell git rev-parse --short=5 HEAD) ./tsidp-server.go

build-linux:
	@mkdir -p build
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o build/tsidp-server-linux-amd64-$(shell date +%Y-%m-%d)-$(shell git rev-parse --short=5 HEAD) ./tsidp-server.go

docker-image:
	docker build -t tsidp:latest .

test:
	go test -count 1  . ./server

clean:
	rm -f build/tsidp-server*
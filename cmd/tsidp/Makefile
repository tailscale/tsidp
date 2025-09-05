.PHONY: build test clean

build:
	@mkdir -p build
	go build -o build/tsidp-server-$(shell date +%Y-%m-%d)-$(shell git rev-parse --short=5 HEAD) ./tsidp-server.go

test:
	go test -v ./oauth ./server ./store

clean:
	rm -f build/tsidp-server*
.PHONY: build test test-verbose vet race clean

build:
	go build -o passman ./cmd/passman

test:
	go test ./...

test-verbose:
	go test -v ./...

vet:
	go vet ./...

race:
	go test -race ./...

clean:
	rm -f passman *_vault.json config.json session.json

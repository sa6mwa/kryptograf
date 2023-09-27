.PHONY: scan clean

all: scan bin/newkey

scan: capslock.json
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go test -v -coverprofile cover.out ./...

clean:
	rm -f capslock.json cover.out bin/newkey
	rmdir bin

cover.lcov:
	go test -v -coverprofile cover.out ./...
	go run github.com/jandelgado/gcov2lcov@latest -infile cover.out -outfile cover.lcov -use-absolute-source-path

README.md:
	go run github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest ./... > README.md

capslock.json:
	go run github.com/google/capslock/cmd/capslock@latest -output json > capslock.json

bin:
	mkdir bin

bin/newkey: bin
	go build -o bin/newkey ./cmd/newkey

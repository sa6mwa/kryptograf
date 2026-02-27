.PHONY: scan clean test bench bench-all bench-stream-focus bench-stream-100m bench-stream-100m-check

BENCH_COUNT ?= 6
BENCH_TIME ?= 200ms
TEST_COUNT ?= 1

all: scan bin/newkey

scan: capslock.json
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go test -v -coverprofile cover.out ./...

test:
	go test -v -cover -count=$(TEST_COUNT) ./...

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

bench: bench-all

bench-all:
	go test ./... -run '^$$' -bench . -benchmem -benchtime=$(BENCH_TIME) -count=$(BENCH_COUNT)

bench-stream-focus:
	go test ./stream -run '^$$' -bench '^BenchmarkDecryptMatrix/(64KiB|256KiB|1MiB|8MiB)/(none|snappy)/(file-section-reader|fragmented-29B)/(default|source-buffer-disabled|source-buffer-forced-8KiB|source-buffer-forced-16KiB|source-buffer-forced-64KiB)$$' -benchmem -benchtime=$(BENCH_TIME) -count=$(BENCH_COUNT)

bench-stream-100m:
	go test ./stream -run '^$$' -bench '^BenchmarkDecryptLarge100MiB$$' -benchmem -benchtime=1x -count=$(BENCH_COUNT)

bench-stream-100m-check:
	go test ./stream -run '^TestDecryptReaderSourceBufferStaysBoundedOnLargePayload$$' -v

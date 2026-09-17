.PHONY: all build generate vet fmt clean

# The syzkaller API comes from the modern tree at ../syzkaller via the go.mod
# replace directive; the old vendor/ tree is no longer used. Requires go 1.26+.
GO ?= go

all: build

build:
	$(GO) build -o ./bin/moonshine .

# Regenerate the ragel/goyacc scanners from their sources. The generated files
# are checked in (they carry the fork's kcov "Cover:" handling), so this is only
# needed after editing scanner/lex.rl or scanner/strace.y.
generate:
	cd scanner && ragel -Z -G2 -o lex.go lex.rl
	cd scanner && goyacc -o strace.go -p Strace strace.y

vet:
	$(GO) vet ./...

fmt:
	gofmt -w $$(gofmt -l . | grep -v 'lex\.go$$' | grep -v 'strace\.go$$')

clean:
	rm -rf bin deserialized corpus.db

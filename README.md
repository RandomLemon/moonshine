# MoonShine: Seed Selection for OS Fuzzers (USENIX '18)

MoonShine selects compact and diverse seeds for OS fuzzers from system call traces of real-world
programs. See the USENIX'18 paper
[MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf).
Currently MoonShine only generates seeds for syzkaller on Linux.

This tree is a fork maintained for the TensorFunnel GPU-fuzzing pipeline. It is vendored into that
repo as the `moonshine/` submodule and **builds against the modern syzkaller** (Go 1.26, module
mode) rather than a private copy of the 2018 one.

## Build and run

Requires Go 1.26+; `ragel`/`goyacc` are only needed for `make generate`.

```bash
make                 # go build -o ./bin/moonshine .
make generate        # regenerate scanner/{lex,strace}.go from the .rl/.y sources
make vet
make fmt
make clean
```

```bash
./bin/moonshine -file /path/to/trace                              # convert only
./bin/moonshine -dir /path/to/tracedir
./bin/moonshine -file trace -distill getting-started/distill.json # convert + distill
```

It writes converted programs to `deserialized/` and packs them into `corpus.db`. Verify before
feeding the corpus to syzkaller — `syz-manager` silently deletes programs that fail to deserialize:

```bash
cd ../syzkaller
go run ./tools/nvidia_corpus_check ../moonshine/corpus.db     # expect: ok=1 bad=0
```

`-vv N` sets verbosity.

## How the syzkaller dependency is wired

`go.mod` pins it with a relative replace:

```
replace github.com/google/syzkaller => ../syzkaller
```

so the module resolves from any checkout location and always tracks the sibling `syzkaller/`
submodule. The old `vendor/github.com/google/syzkaller/` tree has been removed.

That vendored tree was not vanilla 2018 upstream: it carried **fork-only patches to syzkaller
internals** that moonshine's distillers depended on — `ResultArg.Set`/`ResultArg.Uses` (writing the
unexported "args that use this result" set directly) and `Prog.StripDependencies`. Modern syzkaller
keeps that set unexported and maintained only by the `prog.Make*` constructors, and
`prog.validate` requires every entry to still be present in the program. `tracker/relink.go`
therefore reimplements both operations (`StripDependencies`, `RelinkDependencies`) by rebuilding
argument trees through the public API; the distillers call them after each successful
`FillOutMemory`.

## Capture traces

`strace -o trace -s 65500 -v -xx -f -k ./payload`. Do **not** add `-y` (it rewrites `3` into
`3</dev/nvidia0>`, which the parser rejects). Per-call coverage needs the KCOV patch shipped as
`strace_kcov.patch`; the checked-in scanner understands the resulting `"Cover:"` lines.

## Layout

| Path | Contents |
|---|---|
| `main.go` | CLI: parse traces, convert, optionally distill, emit `corpus.db` |
| `scanner/` | strace lexer (`lex.rl`/`lex.go`) and grammar (`strace.y`/`strace.go`) |
| `strace_types/` | strace-side typing, `_IOC` macro evaluation, constant tables |
| `parser/` | IR → syzkaller program generation and preprocess hooks |
| `tracker/` | Memory/resource tracking, state; `relink.go` replaces the old fork patches |
| `distiller/` | Distillation strategies (explicit, implicit, weak, random, trace) |
| `configs/`, `logging/`, `implicit-dependencies/` | Support packages |

## Known limitations

On the real GPU traces (`../data/tf4.trace` and siblings) this tool currently emits an **empty
corpus** — and its pristine 2018 binary does exactly the same, byte for byte. The blockers are
pre-existing design limits, not artifacts of the migration to modern syzkaller:

1. `tracker/memory_tracker.go` caps its allocator at `memAllocMaxMem = 16 << 20`, while the CUDA
   payload reserves ~4.8 GiB of `PROT_NONE` memory that the tracker tries to pack into that region.
2. Raising the cap is not sufficient: the converted program embeds absolute CUDA library paths
   (`/usr/local/cuda-13.1/...`), which syzkaller rejects as sandbox escapes in the mode
   `syz-manager` uses for corpus seeds.
3. A 94 MB VMA cannot fit the target's 16 MiB data region (`NumPages * PageSize`).
4. `fcntl$setstatus` needs an `fd`-typed resource where the trace supplies `fd_event`; the resource
   cache has no dup/device-type awareness.

Tracked as T4–T7 in the TensorFunnel repo's `docs/06-task-board.md`; `trace2syz` already carries
the equivalent fixes.

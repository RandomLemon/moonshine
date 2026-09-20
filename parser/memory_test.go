package parser

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/google/syzkaller/sys"
	"github.com/shankarapailoor/moonshine/scanner"
)

// A real CUDA process maps gigabytes: PROT_NONE address-space reservations, the
// CUDA libraries and megabytes of anonymous heap. A converted program can only
// address the target's data region (16 MiB on linux/amd64), so such mappings
// cannot be relocated into it. Regression: they used to be tracked and pushed
// the program's pointers out of the data region, which made
// MemoryTracker.FillOutMemory reject every converted program and left the
// corpus empty.
const unrepresentableMemoryTrace = `1234 mmap(NULL, 4297064448, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f0000000000
1234 mmap(NULL, 99192584, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f1000000000
1234 mmap(NULL, 2699264, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f2000000000
1234 openat(AT_FDCWD, "\x66\x69\x6c\x65", O_RDONLY) = 3
`

func TestUnrepresentableMappingsDoNotDropProg(t *testing.T) {
	target := testTarget(t)
	name := filepath.Join(t.TempDir(), "huge.trace")
	if err := os.WriteFile(name, []byte(unrepresentableMemoryTrace), 0644); err != nil {
		t.Fatal(err)
	}
	tree := scanner.Parse(name)
	if tree == nil {
		t.Fatal("scanner returned no tree")
	}
	ctx, err := ParseProg(tree.TraceMap[tree.RootPid], target)
	if err != nil {
		t.Fatalf("ParseProg: %v", err)
	}
	// The calls that do not need memory management must survive the conversion.
	if len(ctx.Prog.Calls) == 0 {
		t.Fatal("converted program is empty")
	}
	if err := ctx.State.Tracker.FillOutMemory(ctx.Prog); err != nil {
		t.Fatalf("FillOutMemory: %v", err)
	}
	if err := ValidateProg(target, ctx.Prog); err != nil {
		t.Fatalf("ValidateProg: %v", err)
	}
}

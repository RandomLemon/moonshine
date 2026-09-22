package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/shankarapailoor/moonshine/scanner"
	"github.com/shankarapailoor/moonshine/tracker"
)

// A CUDA process names dozens of absolute paths while starting up: the loader
// libraries, /proc entries, /dev/shm and unix sockets under /tmp. syzkaller
// rejects a program containing any of them ("escaping filename") and
// syz-manager then deletes it from the corpus, so the conversion must drop those
// calls while keeping the device nodes it rebinds to syz_open_dev$*.
//
// Paths that are relative ("glibc-hwcaps/x86-64-v3/libc.so.6") stay: the loader
// opens them relative to the searched directory and syzkaller accepts them.
const absolutePathTrace = `59749 openat(AT_FDCWD, "\x2f\x6c\x69\x62\x2f\x6c\x69\x62\x63\x2e\x73\x6f\x2e\x36\x00", O_RDONLY) = 3
59749 openat(AT_FDCWD, "\x67\x6c\x69\x62\x63\x2f\x6c\x69\x62\x63\x2e\x73\x6f\x2e\x36\x00", O_RDONLY) = 3
59749 openat(AT_FDCWD, "\x2e\x2e\x2f\x6e\x76\x69\x64\x69\x61\x63\x74\x6c\x00", O_RDONLY) = 3
59749 readlink("\x2f\x70\x72\x6f\x63\x2f\x73\x65\x6c\x66\x2f\x65\x78\x65\x00", "\x2f\x75\x73\x72\x00", 4) = 4
59749 stat("\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00", 0x7ffd00000000) = 0
59749 mkdir("\x2f\x74\x6d\x70\x2f\x64\x69\x72\x00", 0700) = 0
59749 connect(10, {sa_family=AF_UNIX, sun_path="\x2f\x74\x6d\x70\x2f\x6e\x76\x69\x64\x69\x61\x2d\x6d\x70\x73\x2f\x63\x6f\x6e\x74\x72\x6f\x6c"}, 26) = -1 ENOENT (No such file or directory)
59749 bind(17, {sa_family=AF_UNIX, sun_path=@"\x63\x75\x64\x61\x2d\x75\x76\x6d\x66\x64\x00"}, 31) = 0
59749 openat(AT_FDCWD, "\x2f\x64\x65\x76\x2f\x6e\x76\x69\x64\x69\x61\x63\x74\x6c\x00", O_RDWR|O_CLOEXEC) = 4
59749 dup(4) = 5
59749 ioctl(5, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2a, 0x20), 0x7ffd00000000) = 0
`

// TestAbsolutePathsAreDropped checks both halves of the filter: every call that
// names a path syzkaller would reject is gone (including the ones whose path is
// nested in a sockaddr), the relative-path open survives, and the device node is
// still opened and rebound.
func TestAbsolutePathsAreDropped(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)
	BuildDeviceBindings(target)

	name := filepath.Join(t.TempDir(), "abs.trace")
	if err := os.WriteFile(name, []byte(absolutePathTrace), 0644); err != nil {
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

	var names []string
	for _, call := range ctx.Prog.Calls {
		names = append(names, call.Meta.Name)
	}
	want := []string{
		"openat",                 // the relative path stays
		"bind",                   // abstract unix socket: no filesystem path, kept
		"syz_open_dev$nvidiactl", // device node, rebound
		"dup$nvidiactl",          // its duplicate keeps the device
		"ioctl$NV_ESC_RM_CONTROL",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("converted calls = %v, want %v", names, want)
	}

	// The remaining calls must be loadable: this is the check that used to
	// panic with "escaping filename" and that syz-manager runs before keeping a
	// corpus program.
	if err := ctx.State.Tracker.FillOutMemory(ctx.Prog); err != nil {
		t.Fatalf("FillOutMemory: %v", err)
	}
	if err := ValidateProg(target, ctx.Prog); err != nil {
		t.Fatalf("ValidateProg: %v", err)
	}
}

// TestPathArgIndex pins which argument of each call syzkaller validates as a
// filename. Getting an index wrong silently keeps an escaping path.
func TestPathArgIndex(t *testing.T) {
	cases := map[string]int{
		"open": 0, "stat": 0, "lstat": 0, "access": 0, "unlink": 0, "readlink": 0,
		"mkdir": 0, "rmdir": 0, "chdir": 0, "chmod": 0, "chown": 0, "truncate": 0,
		"execve": 0,
		"symlink": 1, // the validated path is newpath
		"openat":  1, "newfstatat": 1, "faccessat": 1, "unlinkat": 1, "mkdirat": 1,
		"readlinkat": 1, "fchmodat": 1, "fchownat": 1, "utimensat": 1,
		"ioctl": -1, "write": -1, "dup": -1,
	}
	for call, want := range cases {
		if got := pathArgIndex(call); got != want {
			t.Errorf("pathArgIndex(%q) = %d, want %d", call, got, want)
		}
	}
}

// A descriptor's producer type can be narrower than the type a later call
// declares for it: eventfd2 returns fd_event, while fcntl$setstatus takes fd.
// Typing the reference after the cached (narrower) resource makes prog reject
// the program with "bad arg type fd_event, expect fd", which is what stopped the
// conversion at the first fcntl once the absolute-path calls were dropped.
const facadeMismatchTrace = `59749 eventfd2(0, EFD_CLOEXEC|EFD_NONBLOCK) = 4
59749 fcntl(4, F_SETFL, O_RDONLY|O_NONBLOCK) = 0
`

func TestNarrowerProducerResourceStillUsable(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)
	BuildDeviceBindings(target)

	name := filepath.Join(t.TempDir(), "fd.trace")
	if err := os.WriteFile(name, []byte(facadeMismatchTrace), 0644); err != nil {
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
	if len(ctx.Prog.Calls) != 2 {
		t.Fatalf("converted %d calls, want 2", len(ctx.Prog.Calls))
	}
	if got := ctx.Prog.Calls[1].Meta.Name; got != "fcntl$setstatus" {
		t.Errorf("second call = %q, want fcntl$setstatus", got)
	}
	if err := ctx.State.Tracker.FillOutMemory(ctx.Prog); err != nil {
		t.Fatalf("FillOutMemory: %v", err)
	}
	if err := ValidateProg(target, ctx.Prog); err != nil {
		t.Fatalf("ValidateProg: %v", err)
	}
}

// get_mempolicy's fourth argument is a bare vma range. The tracker packs
// arguments back to back, so such a range starts at an arbitrary offset;
// prog.MakeVmaPointerArg panics on an address that is not 1024-aligned
// ("unaligned vma address"), which the distill path used to hit for every
// program whose predecessor left the offset unaligned.
const vmaAlignmentTrace = `59749 openat(AT_FDCWD, "\x61\x62\x63\x00", O_RDONLY) = 3
59749 get_mempolicy([MPOL_DEFAULT], [000000000000000000], 64, NULL, 0) = 0
`

func TestVmaArgumentIsAligned(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)
	BuildDeviceBindings(target)

	name := filepath.Join(t.TempDir(), "vma.trace")
	if err := os.WriteFile(name, []byte(vmaAlignmentTrace), 0644); err != nil {
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
	total := ctx.State.Tracker.GetTotalMemoryAllocations(ctx.Prog)
	ctx.Prog.Calls = append([]*prog.Call{tracker.MakeMmap(target, 0, total)}, ctx.Prog.Calls...)
	if err := ctx.State.Tracker.FillOutMemory(ctx.Prog); err != nil {
		t.Fatalf("FillOutMemory: %v", err)
	}
	if err := ValidateProg(target, ctx.Prog); err != nil {
		t.Fatalf("ValidateProg: %v", err)
	}
	for _, call := range ctx.Prog.Calls {
		if call.Meta.Name != "get_mempolicy" {
			continue
		}
		arg, ok := call.Args[3].(*prog.PointerArg)
		if !ok {
			t.Fatalf("addr argument is %T, want pointer", call.Args[3])
		}
		if arg.Address%1024 != 0 {
			t.Errorf("vma address %#x is not 1024-aligned", arg.Address)
		}
		if arg.Address+arg.VmaSize > total {
			t.Errorf("vma range %#x+%#x leaves the data region of %#x", arg.Address, arg.VmaSize, total)
		}
	}
}

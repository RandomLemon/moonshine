package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/shankarapailoor/moonshine/scanner"
)

// A CUDA process opens the three NVIDIA device nodes it drives, duplicates two
// of the descriptors and issues device commands through the duplicates. strace
// prints the paths NUL-terminated; the resource type of a descriptor is the
// first component of every device variant key, so a descriptor that is not
// bound to its device selects no device-specific variant at all.
const nvidiaDeviceTrace = `59749 openat(AT_FDCWD, "\x2f\x64\x65\x76\x2f\x6e\x76\x69\x64\x69\x61\x63\x74\x6c\x00", O_RDWR|O_CLOEXEC) = 3
59749 openat(AT_FDCWD, "\x2f\x64\x65\x76\x2f\x6e\x76\x69\x64\x69\x61\x37\x00", O_RDWR|O_CLOEXEC) = 5
59749 openat(AT_FDCWD, "\x2f\x64\x65\x76\x2f\x6e\x76\x69\x64\x69\x61\x2d\x75\x76\x6d\x00", O_RDWR|O_CLOEXEC) = 4
59749 dup(3) = 6
59749 dup(5) = 7
59749 ioctl(6, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2a, 0x20), 0x7ffd00000000) = 0
59749 ioctl(7, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x29, 0x10), 0x7ffd00000000) = 0
59749 ioctl(4, 0x30000001, 0x7ffd00000000) = 0
`

// TestDeviceBindings pins open binding, dup type preservation and the ioctl
// variant selection they enable, in one pass: the whole point of the device
// identity is that a command issued on a duplicated descriptor is still named
// after the device it was opened on.
func TestDeviceBindings(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)
	BuildDeviceBindings(target)

	name := filepath.Join(t.TempDir(), "devices.trace")
	if err := os.WriteFile(name, []byte(nvidiaDeviceTrace), 0644); err != nil {
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

	want := []string{
		"syz_open_dev$nvidiactl",   // openat /dev/nvidiactl
		"syz_open_dev$nvidia",      // openat /dev/nvidia7, device index captured
		"syz_open_dev$nvidia_uvm",  // openat /dev/nvidia-uvm
		"dup$nvidiactl",            // dup of the control descriptor
		"dup$nvidia",               // dup of the card descriptor
		"ioctl$NV_ESC_RM_CONTROL",  // control command through the duplicate
		"ioctl$NV_ESC_RM_FREE_dev", // device command through the duplicate
		"ioctl$UVM_INITIALIZE",     // uvm command, selected by command value
	}
	var got []string
	for _, call := range ctx.Prog.Calls {
		got = append(got, call.Meta.Name)
	}
	if len(got) != len(want) {
		t.Fatalf("converted %d calls, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call #%d = %q, want %q", i, got[i], want[i])
		}
	}

	// The captured device index and the path must agree: the executor opens the
	// path with every '#' replaced by a digit of the index.
	card := ctx.Prog.Calls[1]
	id, ok := card.Args[1].(*prog.ConstArg)
	if !ok {
		t.Fatalf("card open: id argument is %T, want const", card.Args[1])
	}
	if id.Val != 7 {
		t.Errorf("card open: id = %d, want 7", id.Val)
	}
	dev, ok := card.Args[0].(*prog.PointerArg)
	if !ok {
		t.Fatalf("card open: dev argument is %T, want pointer", card.Args[0])
	}
	buf, ok := dev.Res.(*prog.DataArg)
	if !ok {
		t.Fatalf("card open: dev buffer is %T, want data", dev.Res)
	}
	if got := strings.TrimRight(string(buf.Data()), "\x00"); got != "/dev/nvidia7" {
		t.Errorf("card open: dev path = %q, want %q", got, "/dev/nvidia7")
	}

	if err := ctx.State.Tracker.FillOutMemory(ctx.Prog); err != nil {
		t.Fatalf("FillOutMemory: %v", err)
	}
	if err := ValidateProg(target, ctx.Prog); err != nil {
		t.Fatalf("ValidateProg: %v", err)
	}
}

// TestOpenDevPatternMatchPath pins the '#' wildcard of syz_open_dev templates,
// including that a longer device index is not silently truncated into a match.
func TestOpenDevPatternMatchPath(t *testing.T) {
	card := openDevPattern{pattern: "/dev/nvidia#", suffix: "nvidia"}
	ctl := openDevPattern{pattern: "/dev/nvidiactl", suffix: "nvidiactl"}
	cases := []struct {
		pat  openDevPattern
		path string
		want bool
		id   int
	}{
		{card, "/dev/nvidia0", true, 0},
		{card, "/dev/nvidia7", true, 7},
		{card, "/dev/nvidia#", true, -1}, // a literal '#' matches, no index captured
		{card, "/dev/nvidia10", false, -1},
		{card, "/dev/nvidia", false, -1},
		{card, "/dev/nvidiactl", false, -1}, // same length, non-digit in the wildcard
		{ctl, "/dev/nvidiactl", true, -1},
		{ctl, "/dev/nvidia7", false, -1},
	}
	for _, c := range cases {
		matched, id := c.pat.matchPath(c.path)
		if matched != c.want {
			t.Errorf("%q ~ %q = %v, want %v", c.pat.pattern, c.path, matched, c.want)
		}
		if matched && id != c.id {
			t.Errorf("%q ~ %q captured id %d, want %d", c.pat.pattern, c.path, id, c.id)
		}
	}
}

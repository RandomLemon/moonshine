package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shankarapailoor/moonshine/scanner"
)

// NV_ESC_CARD_INFO is described as ptr[out, array[nv_ioctl_card_info, 32]] and
// the decoder prints the single populated entry as a struct. An array whose
// element arrives as a struct has to be accepted, or the whole trace is
// rejected ("Error parsing Array: array with Wrong Type: Struct Type") and the
// corpus comes out empty.
//
// The second ioctl covers the modelled case: its struct must be converted into
// the corresponding positional argument, not dropped.
const cardInfoTrace = `59749 openat(AT_FDCWD, "\x2f\x64\x65\x76\x2f\x6e\x76\x69\x64\x69\x61\x63\x74\x6c\x00", O_RDWR|O_CLOEXEC) = 4
59749 ioctl(4, NV_ESC_CARD_INFO, {valid=0x1, pci_info={domain=0x0, bus=0x64, slot=0x0, function=0x0, vendor_id=0x10de, device_id=0x28e0}, gpu_id=0x6400, interrupt_line=0x95, reg_address=0xdc000000, reg_size=0x1000000, fb_address=0x7800000000, fb_size=0x200000000, minor_number=0x0}) = 0
59749 ioctl(4, NV_ESC_RM_CONTROL, {h_client=0x2b, h_object=0x2b, cmd=0x2080012d, flags=0x0, params=0x7ffd00000000, params_size=0x10, status=0}) = 0
`

func TestArrayOfStructArgumentConverts(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)
	BuildDeviceBindings(target)

	name := filepath.Join(t.TempDir(), "cardinfo.trace")
	if err := os.WriteFile(name, []byte(cardInfoTrace), 0644); err != nil {
		t.Fatal(err)
	}
	tree := scanner.Parse(name)
	if tree == nil {
		t.Fatal("scanner returned no tree")
	}
	// ParseProg fails the test if the struct-in-array case is missing: it
	// calls Failf, which panics.
	ctx, err := ParseProg(tree.TraceMap[tree.RootPid], target)
	if err != nil {
		t.Fatalf("ParseProg: %v", err)
	}

	var names []string
	for _, call := range ctx.Prog.Calls {
		names = append(names, call.Meta.Name)
	}
	want := []string{"syz_open_dev$nvidiactl", "ioctl$NV_ESC_CARD_INFO", "ioctl$NV_ESC_RM_CONTROL"}
	if len(names) != len(want) {
		t.Fatalf("calls = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("call %d = %s, want %s", i, names[i], want[i])
		}
	}
}

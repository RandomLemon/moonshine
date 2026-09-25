package parser

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/shankarapailoor/moonshine/strace_types"
)

const (
	cmdRMAlloc        = uint64(3224389163) // 0xc030462b NV_ESC_RM_ALLOC
	cmdAllocOSEvent   = uint64(3222292174) // 0xc01046ce NV_ESC_ALLOC_OS_EVENT
	cmdRMANocMemory   = uint64(3224913447) // 0xc0384627 NV_ESC_RM_ALLOC_MEMORY
	cmdRMNumaInfo     = uint64(3257943767) // 0xc23046d7 NV_ESC_NUMA_INFO
	cmdRMMapMemoryDev = uint64(3224913486) // 0xc038464e NV_ESC_RM_MAP_MEMORY
)

// newNamedIoctlCtx drives Preprocess_Ioctl with a command printed as a symbolic
// name and an fd opened as fdName ("" leaves the fd unbound).
func newNamedIoctlCtx(t *testing.T, target *prog.Target, fdName, cmdName string) *Context {
	t.Helper()
	ctx := NewContext(target)
	ctx.CurrentSyzCall = &prog.Call{Meta: target.SyscallMap["ioctl"]}
	fdExpr := strace_types.NewExpression(strace_types.NewIntType(10))
	if fdName != "" {
		fdRes := testFdResource(t, target, fdName)
		ctx.Cache.Cache(fdRes, fdExpr, prog.MakeResultArg(fdRes, prog.DirOut, nil, 10))
	}
	ctx.CurrentStraceCall = strace_types.NewSyscall(1, "ioctl", []strace_types.Type{
		fdExpr,
		strace_types.NewExpression(strace_types.NewFlagType(cmdName)),
	}, 0, false, false)
	Preprocess_Ioctl(ctx)
	return ctx
}

// TestNamedIoctlUsesFdDeviceVariant pins the fix for variants the description
// models once per device under a single printed name. /dev/nvidiactl and
// /dev/nvidia0 both accept NV_ESC_RM_ALLOC and strace prints that one spelling
// for either, so the printed name alone resolves to whichever variant the
// syscall map holds - always the control-device one. A program that opened
// /dev/nvidia0 must get the _dev variant, as the Open/dup binding established.
func TestNamedIoctlUsesFdDeviceVariant(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)

	cases := []struct {
		fd   string
		cmd  string
		want string
	}{
		{"fd_nvidia_dev", "NV_ESC_RM_ALLOC", "ioctl$NV_ESC_RM_ALLOC_dev"},
		{"fd_nvidiactl", "NV_ESC_RM_ALLOC", "ioctl$NV_ESC_RM_ALLOC"},
		{"fd_nvidia_dev", "NV_ESC_ALLOC_OS_EVENT", "ioctl$NV_ESC_ALLOC_OS_EVENT_dev"},
		{"fd_nvidiactl", "NV_ESC_ALLOC_OS_EVENT", "ioctl$NV_ESC_ALLOC_OS_EVENT"},
		{"fd_nvidia_dev", "NV_ESC_RM_ALLOC_MEMORY", "ioctl$NV_ESC_RM_ALLOC_MEMORY_dev"},
		{"fd_nvidiactl", "NV_ESC_RM_ALLOC_MEMORY", "ioctl$NV_ESC_RM_ALLOC_MEMORY"},
		{"fd_nvidiactl", "NV_ESC_RM_MAP_MEMORY", "ioctl$NV_ESC_RM_MAP_MEMORY"},
		// NUMA_INFO is not declared for the control device, so on that fd the
		// printed name has to keep deciding; picking the dev variant there would
		// be as wrong as the case above.
		{"fd_nvidia_dev", "NV_ESC_NUMA_INFO", "ioctl$NV_ESC_NUMA_INFO"},
		// The name path still owns commands that are not modelled per device.
		{"fd_nvidia_uvm", "UVM_INITIALIZE", "ioctl$UVM_INITIALIZE"},
	}
	for _, c := range cases {
		ctx := newNamedIoctlCtx(t, target, c.fd, c.cmd)
		if got := ctx.CurrentStraceCall.CallName; got != c.want {
			t.Errorf("fd=%-14s cmd=%-22s: selected %q, want %q", c.fd, c.cmd, got, c.want)
		}
	}
}

// TestNamedIoctlWithoutFdBindingKeepsName: with no Open/dup hook binding the fd
// there is no device to consult, so the printed name decides. This is how a
// command issued on an fd the trace never opened still gets its variant.
func TestNamedIoctlWithoutFdBindingKeepsName(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)
	ctx := newNamedIoctlCtx(t, target, "", "NV_ESC_RM_ALLOC")
	if got, want := ctx.CurrentStraceCall.CallName, "ioctl$NV_ESC_RM_ALLOC"; got != want {
		t.Fatalf("selected %q, want %q", got, want)
	}
}

// TestNamedIoctlUnknownConstantFallsBackToName: a name strace printed but the
// target has no constant for must not abort the trace while the device table is
// consulted. The name is unmodelled, so the plain ioctl is the only answer.
func TestNamedIoctlUnknownConstantFallsBackToName(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)
	ctx := newNamedIoctlCtx(t, target, "fd_nvidia_dev", "NV_ESC_QUERY_DEVICE_INTR")
	if got, want := ctx.CurrentStraceCall.CallName, "ioctl"; got != want {
		t.Fatalf("selected %q, want %q", got, want)
	}
}

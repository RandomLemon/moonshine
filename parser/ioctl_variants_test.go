package parser

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/shankarapailoor/moonshine/strace_types"
)

const (
	cmdRMControl = uint64(3223340586) // 0xc020462a NV_ESC_RM_CONTROL
	cmdRMFREE    = uint64(3222292009) // 0xc0104629 NV_ESC_RM_FREE
	cmdUVMInit   = uint64(805306369)  // 0x30000001 UVM_INITIALIZE
	cmdFIONBIO   = uint64(21537)      // 0x5421 FIONBIO, declared on plain `fd` only
)

func testTarget(t *testing.T) *prog.Target {
	t.Helper()
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func testFdResource(t *testing.T, target *prog.Target, name string) *prog.ResourceType {
	t.Helper()
	var typ prog.Type
	switch name {
	case "fd":
		typ = target.SyscallMap["ioctl"].Args[0].Type
	case "fd_event":
		typ = target.SyscallMap["eventfd2"].Ret
	case "fd_nvidiactl":
		typ = target.SyscallMap["syz_open_dev$nvidiactl"].Ret
	case "fd_nvidia_dev":
		typ = target.SyscallMap["syz_open_dev$nvidia"].Ret
	case "fd_nvidia_uvm":
		typ = target.SyscallMap["syz_open_dev$nvidia_uvm"].Ret
	default:
		t.Fatalf("unknown resource %q", name)
	}
	res, ok := typ.(*prog.ResourceType)
	if !ok {
		t.Fatalf("%q: not a resource type: %v", name, typ)
	}
	return res
}

// runIoctlHook drives Preprocess_Ioctl with an fd opened as fdRes.
func runIoctlHook(t *testing.T, target *prog.Target, fdRes *prog.ResourceType, fd, cmd uint64) string {
	t.Helper()
	ctx := NewContext(target)
	ctx.CurrentSyzCall = &prog.Call{Meta: target.SyscallMap["ioctl"]}
	fdExpr := strace_types.NewExpression(strace_types.NewIntType(int64(fd)))
	ctx.Cache.Cache(fdRes, fdExpr, prog.MakeResultArg(fdRes, prog.DirOut, nil, fd))
	ctx.CurrentStraceCall = strace_types.NewSyscall(1, "ioctl", []strace_types.Type{
		fdExpr,
		strace_types.NewExpression(strace_types.NewIntType(int64(cmd))),
	}, 0, false, false)
	Preprocess_Ioctl(ctx)
	if ctx.CurrentSyzCall.Meta == nil {
		t.Fatalf("fd=%s cmd=%#x: hook left Meta nil", fdRes.TypeName, cmd)
	}
	return ctx.CurrentStraceCall.CallName
}

// TestIoctlVariantByValue pins the value-based variant selection: strace prints
// ioctl commands as _IOC(...) macros, which evaluate to numbers, so the
// (fd resource, command value) table is the only way to name them.
func TestIoctlVariantByValue(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)

	spot := []struct {
		fd   string
		cmd  uint64
		want string
	}{
		{"fd_nvidiactl", cmdRMControl, "NV_ESC_RM_CONTROL"},
		{"fd_nvidiactl", cmdUVMInit, ""},
		{"fd_nvidia_uvm", cmdUVMInit, "UVM_INITIALIZE"},
		{"fd_nvidia_dev", cmdRMFREE, "NV_ESC_RM_FREE_dev"},
	}
	for _, c := range spot {
		if got := lookupIoctlVariant(testFdResource(t, target, c.fd), c.cmd); got != c.want {
			t.Errorf("lookupIoctlVariant(%s, %#x) = %q, want %q", c.fd, c.cmd, got, c.want)
		}
	}

	fionbio := lookupIoctlVariant(testFdResource(t, target, "fd"), cmdFIONBIO)
	if fionbio == "" {
		t.Fatal("no plain-fd variant registered for FIONBIO")
	}
	cases := []struct {
		fd   string
		cmd  uint64
		want string
	}{
		// NV_ESC_RM_CONTROL is valid on the control device and on /dev/nvidiaN,
		// and the two variants must stay distinct.
		{"fd_nvidiactl", cmdRMControl, "ioctl$NV_ESC_RM_CONTROL"},
		{"fd_nvidia_dev", cmdRMControl, "ioctl$NV_ESC_RM_CONTROL_dev"},
		{"fd_nvidia_uvm", cmdUVMInit, "ioctl$UVM_INITIALIZE"},
		// A UVM command on the control device is not a variant: falling back to
		// the generic ioctl is correct, and picking the uvm one would be wrong.
		{"fd_nvidiactl", cmdUVMInit, "ioctl"},
		// Without a device binding the fd is a plain fd, so no device variant
		// may be selected; this is what makes open binding a prerequisite.
		{"fd", cmdRMControl, "ioctl"},
		// The fd's Kind chain is walked down to the root, so variants declared
		// on plain `fd` still match more specific descriptors.
		{"fd_event", cmdFIONBIO, "ioctl$" + fionbio},
	}
	for _, c := range cases {
		if got := runIoctlHook(t, target, testFdResource(t, target, c.fd), 10, c.cmd); got != c.want {
			t.Errorf("fd=%-14s cmd=%#x: hook selected %q, want %q", c.fd, c.cmd, got, c.want)
		}
	}
}

// TestIoctlVariantsNameStillFirst keeps the strace-name path ahead of the value
// table: once strace prints NV_ESC_* names, they must decide the variant.
func TestIoctlVariantsNameStillFirst(t *testing.T) {
	target := testTarget(t)
	BuildIoctlVariants(target)
	ctx := NewContext(target)
	ctx.CurrentSyzCall = &prog.Call{Meta: target.SyscallMap["ioctl"]}
	ctx.CurrentStraceCall = strace_types.NewSyscall(1, "ioctl", []strace_types.Type{
		strace_types.NewExpression(strace_types.NewIntType(10)),
		strace_types.NewExpression(strace_types.NewFlagType("NV_ESC_RM_CONTROL")),
	}, 0, false, false)
	Preprocess_Ioctl(ctx)
	if got, want := ctx.CurrentStraceCall.CallName, "ioctl$NV_ESC_RM_CONTROL"; got != want {
		t.Fatalf("selected %q, want %q", got, want)
	}
}

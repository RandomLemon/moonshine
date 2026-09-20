package parser

import (
	"strings"

	"github.com/google/syzkaller/prog"
)

// ioctlVariantKey identifies an ioctl variant by the device resource of its fd
// argument and the value of its constant command argument.
//
// The resource component is the variant's own resource type (TypeName), e.g.
// "fd_nvidiactl", not the generic root kind ("fd"): NV_ESC_RM_CONTROL is a
// valid command for both /dev/nvidiactl and /dev/nvidia0, and keying on the
// root kind would make those two variants collide.
type ioctlVariantKey struct {
	fdType string
	cmd    uint64
}

// ioctlVariants maps (fd resource, command value) to the ioctl$<suffix> variant
// name suffix. Built once by BuildIoctlVariants before traces are parsed.
var ioctlVariants map[ioctlVariantKey]string

// BuildIoctlVariants records the (fd resource, command value) pair of every
// ioctl$* variant. strace prints ioctl commands as _IOC(...) macros, which
// evaluate to numbers rather than names, so the name-keyed maps
// (strace_types.Ioctl_map, SyscallMap["ioctl$<name>"]) never match; the value
// table is what selects a variant for such traces.
//
// Duplicate keys keep the first variant seen, which also mirrors
// trace2syz's buildIoctlMap (modern descriptions contain sibling variants with
// identical (resource, cmd) pairs, and overwriting would pick arbitrarily).
func BuildIoctlVariants(target *prog.Target) {
	m := make(map[ioctlVariantKey]string)
	for _, call := range target.Syscalls {
		if call.CallName != "ioctl" || !strings.Contains(call.Name, "$") {
			continue
		}
		res, ok := call.Args[0].Type.(*prog.ResourceType)
		if !ok {
			continue
		}
		suffix := strings.Split(call.Name, "$")[1]
		switch a := call.Args[1].Type.(type) {
		case *prog.ConstType:
			key := ioctlVariantKey{res.TypeName, a.Val}
			if _, exists := m[key]; !exists {
				m[key] = suffix
			}
		case *prog.FlagsType:
			for _, v := range a.Vals {
				key := ioctlVariantKey{res.TypeName, v}
				if _, exists := m[key]; !exists {
					m[key] = suffix
				}
			}
		}
	}
	ioctlVariants = m
}

// lookupIoctlVariant returns the variant suffix registered for cmd on res, or
// "" if the device does not implement cmd.
//
// The fd argument seen at runtime can carry a more generic resource type than
// the one a variant is declared on, so the resource's Kind chain is walked from
// the most specific type (res itself, the last Kind entry) to the root ("fd").
// A missing key is meaningful: a command that exists for /dev/nvidiactl but not
// for /dev/nvidia-uvm must not select the ctl variant when issued on the uvm fd.
func lookupIoctlVariant(res *prog.ResourceType, cmd uint64) string {
	if ioctlVariants == nil {
		return ""
	}
	for i := len(res.Desc.Kind) - 1; i >= 0; i-- {
		if suffix, ok := ioctlVariants[ioctlVariantKey{res.Desc.Kind[i], cmd}]; ok {
			return suffix
		}
	}
	return ""
}

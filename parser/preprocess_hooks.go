package parser

import (
	"github.com/google/syzkaller/prog"
	. "github.com/shankarapailoor/moonshine/logging"
	"github.com/shankarapailoor/moonshine/strace_types"
)

type PreprocessHook func(ctx *Context)

func Preprocess(ctx *Context) {
	call := ctx.CurrentStraceCall.CallName
	if procFunc, ok := PreprocessMap[call]; ok {
		procFunc(ctx)
	}
	return
}

var PreprocessMap = map[string]PreprocessHook{
	"bpf":         Preprocess_Bpf,
	"accept":      Preprocess_Accept,
	"accept4":     Preprocess_Accept,
	"bind":        Preprocess_Bind,
	"connect":     Preprocess_Connect,
	"dup":         Preprocess_Dup,
	"dup2":        Preprocess_Dup,
	"dup3":        Preprocess_Dup,
	"fcntl":       Preprocess_Fcntl,
	"getsockname": Preprocess_Getsockname,
	"getsockopt":  Preprocess_Getsockopt,
	"ioctl":       Preprocess_Ioctl,
	"open":        Preprocess_Open,
	"prctl":       Preprocess_Prctl,
	"recvfrom":    Preprocess_Recvfrom,
	"mknod":       Preprocess_Mknod,
	"modify_ldt":  Preprocess_ModifyLdt,
	"openat":      Preprocess_Openat,
	"sendto":      Preprocess_Sendto,
	"setsockopt":  Preprocess_Setsockopt,
	"shmctl":      Preprocess_Shmctl,
	"socket":      Preprocess_Socket,
}

func Preprocess_Bpf(ctx *Context) {
	bpfCmd := ctx.CurrentStraceCall.Args[0].String()
	if suffix, ok := strace_types.Bpf_labels[bpfCmd]; ok {
		ctx.CurrentStraceCall.CallName += suffix
	} else if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+bpfCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + bpfCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func Preprocess_Accept(ctx *Context) {
	/*
		Accept can take on many subforms such as
		accept$inet
		accept$inet6

		In order to determine the proper form we need to look at the file descriptor to determine
		the proper socket type. We refer to the $inet as a suffix to the name
	*/
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0] //File descriptor of Accept
	syzFd := ctx.CurrentSyzCall.Meta.Args[0].Type
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = strace_types.Accept_labels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func Preprocess_Bind(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0].Type
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = strace_types.Bind_labels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func Preprocess_Connect(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0].Type
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = strace_types.Connect_labels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func Preprocess_Getsockname(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0].Type
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = strace_types.Getsockname_labels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func Preprocess_Socket(ctx *Context) {
	straceFd := ctx.CurrentStraceCall.Args[0]

	if suffix, ok := strace_types.Socket_labels[straceFd.String()]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}
}

func Preprocess_Setsockopt(ctx *Context) {
	sockLevel := ctx.CurrentStraceCall.Args[1]
	optName := ctx.CurrentStraceCall.Args[2]
	pair := strace_types.Pair{
		A: sockLevel.String(),
		B: optName.String(),
	}
	if suffix, ok := strace_types.Setsockopt_labels[pair]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}

}

func Preprocess_Getsockopt(ctx *Context) {
	sockLevel := ctx.CurrentStraceCall.Args[1]
	optName := ctx.CurrentStraceCall.Args[2]
	pair := strace_types.Pair{
		A: sockLevel.String(),
		B: optName.String(),
	}
	if suffix, ok := strace_types.Getsockopt_labels[pair]; ok {
		ctx.CurrentStraceCall.CallName += suffix
		ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
	}

}

func Preprocess_Recvfrom(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0]
	syzFd := ctx.CurrentSyzCall.Meta.Args[0].Type
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = strace_types.Recvfrom_labels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func Preprocess_Open(ctx *Context) {
	if selectOpenDev(ctx, 0) {
		return
	}
	if len(ctx.CurrentStraceCall.Args) < 3 {
		ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
			strace_types.NewExpression(strace_types.NewIntType(int64(0))))
	}
}

func Preprocess_Mknod(ctx *Context) {
	if len(ctx.CurrentStraceCall.Args) < 3 {
		ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
			strace_types.NewExpression(strace_types.NewIntType(int64(0))))
	}
}

func Preprocess_Openat(ctx *Context) {
	if selectOpenDev(ctx, 1) {
		return
	}
	if len(ctx.CurrentSyzCall.Args) < 4 {
		ctx.CurrentStraceCall.Args = append(ctx.CurrentStraceCall.Args,
			strace_types.NewExpression(strace_types.NewIntType(int64(0))))
	}
}

// Preprocess_Dup keeps the device identity of a duplicated descriptor. The
// generic dup/dup2/dup3 return a plain fd, so without the variant every later
// ioctl on the duplicate falls back to the unconstrained ioctl description.
func Preprocess_Dup(ctx *Context) {
	suffix, ok := dupVariantSuffix(ctx)
	if !ok {
		return
	}
	name := ctx.CurrentStraceCall.CallName + "$" + suffix
	if meta, ok := ctx.Target.SyscallMap[name]; ok {
		ctx.CurrentSyzCall.Meta = meta
	}
}

func Preprocess_Ioctl(ctx *Context) {
	suffix := ioctlVariantSuffixFor(ctx, ctx.CurrentStraceCall.Args[1].String())
	ctx.CurrentStraceCall.CallName += suffix
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

// ioctlVariantSuffixFor decides which ioctl$* variant a call names and returns
// the suffix to append ("" for the plain ioctl).
//
// Three sources are consulted:
//  1. Ioctl_map, the hand-written table of strace command names whose
//     description counterpart carries a different suffix (FIONBIO and friends);
//  2. the (device resource, command value) table, which is what separates
//     variants sharing one printed name - NV_ESC_RM_ALLOC is declared for both
//     /dev/nvidiactl and /dev/nvidiaN under that single name;
//  3. the printed name itself, which decides when the fd was not tracked.
func ioctlVariantSuffixFor(ctx *Context, name string) string {
	if suffix, ok := strace_types.Ioctl_map[name]; ok {
		return suffix
	}
	byName := ""
	if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+name]; ok {
		byName = "$" + name
	}
	// A printed command name identifies the command but not the device it was
	// issued on, and the description models those as separate variants with
	// identical spelling, so the name can only ever resolve to the one the map
	// holds. When that variant is not declared for this call's device, the
	// (device, value) table is the only source that can tell them apart.
	if !ioctlNameDeclaredForFd(ctx, name) {
		if byValue := ioctlVariantSuffix(ctx); byValue != "" {
			// The table stores the variant name up to its first '$', which for
			// doubly-suffixed variants is a prefix rather than a syscall, so
			// only accept an answer that names one.
			if _, ok := ctx.Target.SyscallMap["ioctl$"+byValue]; ok {
				return "$" + byValue
			}
		}
	}
	return byName
}

// ioctlNameDeclaredForFd reports whether ioctl$<name> is declared on the device
// the ioctl fd argument was opened as. It is true when the fd was not tracked,
// since there is then nothing to contradict the printed name.
func ioctlNameDeclaredForFd(ctx *Context, name string) bool {
	meta, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+name]
	if !ok {
		return false
	}
	declared, ok := meta.Args[0].Type.(*prog.ResourceType)
	if !ok {
		return true
	}
	res := ioctlFdResource(ctx)
	if res == nil {
		return true
	}
	for _, kind := range res.Desc.Kind {
		if kind == declared.TypeName {
			return true
		}
	}
	return false
}

// ioctlFdResource returns the resource type the ioctl fd argument was opened as,
// or nil when no open/dup hook bound it.
func ioctlFdResource(ctx *Context) *prog.ResourceType {
	if len(ctx.CurrentStraceCall.Args) < 1 {
		return nil
	}
	syzFd, ok := ctx.CurrentSyzCall.Meta.Args[0].Type.(*prog.ResourceType)
	if !ok {
		return nil
	}
	arg := ctx.Cache.Get(syzFd, ctx.CurrentStraceCall.Args[0])
	if arg == nil {
		return nil
	}
	res, ok := arg.Type().(*prog.ResourceType)
	if !ok {
		return nil
	}
	return res
}

// ioctlVariantSuffix resolves the fd argument to the device resource it was
// opened as and looks the command value up in the variant table.
func ioctlVariantSuffix(ctx *Context) string {
	res := ioctlFdResource(ctx)
	if res == nil {
		return ""
	}
	cmd, ok := ctx.CurrentStraceCall.Args[1].(*strace_types.Expression)
	if !ok {
		return ""
	}
	value, ok := ioctlCmdValue(ctx, cmd)
	if !ok {
		return ""
	}
	return lookupIoctlVariant(res, value)
}

// ioctlCmdValue evaluates an ioctl command argument, reporting failure instead
// of panicking: strace_types evaluates names through the target's constant map
// and aborts the process on a name it does not define, but a command that has no
// constant is one the description does not model, and for those the printed name
// is the only answer either way.
func ioctlCmdValue(ctx *Context, cmd *strace_types.Expression) (value uint64, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = 0, false
		}
	}()
	return cmd.Eval(ctx.Target), true
}

func Preprocess_Fcntl(ctx *Context) {
	fcntlCmd := ctx.CurrentStraceCall.Args[1].String()
	if suffix, ok := strace_types.Fcntl_labels[fcntlCmd]; ok {
		ctx.CurrentStraceCall.CallName += suffix
	} else if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+fcntlCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + fcntlCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func Preprocess_Prctl(ctx *Context) {
	prctlCmd := ctx.CurrentStraceCall.Args[0].String()
	if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+prctlCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + prctlCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func Preprocess_Shmctl(ctx *Context) {
	shmctlCmd := ctx.CurrentStraceCall.Args[1].String()
	if _, ok := ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName+"$"+shmctlCmd]; ok {
		ctx.CurrentStraceCall.CallName += "$" + shmctlCmd
	}
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

func Preprocess_Sendto(ctx *Context) {
	suffix := ""
	straceFd := ctx.CurrentStraceCall.Args[0] //File descriptor of Accept
	syzFd := ctx.CurrentSyzCall.Meta.Args[0].Type
	if arg := ctx.Cache.Get(syzFd, straceFd); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			if suffix = strace_types.Sendto_labels[a.TypeName]; suffix != "" {
				ctx.CurrentStraceCall.CallName += suffix
				ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
			}
		}
	}
}

func Preprocess_ModifyLdt(ctx *Context) {
	suffix := ""
	switch a := ctx.CurrentStraceCall.Args[0].(type) {
	case *strace_types.Expression:
		switch a.Eval(ctx.Target) {
		case 0:
			suffix = "$read"
		case 1:
			suffix = "$write"
		case 2:
			suffix = "$read_default"
		case 17:
			suffix = "$write2"
		}
	default:
		Failf("Preprocess modifyldt received unexpected strace type: %s\n", a.Name())
	}
	ctx.CurrentStraceCall.CallName = ctx.CurrentStraceCall.CallName + suffix
	ctx.CurrentSyzCall.Meta = ctx.Target.SyscallMap[ctx.CurrentStraceCall.CallName]
}

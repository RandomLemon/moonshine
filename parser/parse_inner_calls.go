package parser

import (
	"github.com/google/syzkaller/prog"
	. "github.com/shankarapailoor/moonshine/logging"
	"github.com/shankarapailoor/moonshine/strace_types"
)

func ParseInnerCall(syzType prog.Type, dir prog.Dir, straceType *strace_types.Call, ctx *Context) prog.Arg {
	switch straceType.CallName {
	case "htons":
		return parse_HtonsHtonl(syzType, dir, straceType, ctx)
	case "htonl":
		return parse_HtonsHtonl(syzType, dir, straceType, ctx)
	case "inet_addr":
		return parse_InetAddr(syzType, dir, straceType, ctx)
	case "inet_pton":
		return parse_InetPton(syzType, dir, straceType, ctx)
	case "makedev":
		return parse_Makedev(syzType, dir, straceType, ctx)
	default:
		Failf("Inner Call: %s Unsupported", straceType.CallName)
	}
	return nil
}

func parse_Makedev(syzType prog.Type, dir prog.Dir, straceType *strace_types.Call, ctx *Context) prog.Arg {
	var major, minor, id int64

	arg1 := straceType.Args[0].(*strace_types.Expression)
	arg2 := straceType.Args[1].(*strace_types.Expression)
	major = int64(arg1.Eval(ctx.Target))
	minor = int64(arg2.Eval(ctx.Target))

	id = ((minor & 0xff) | ((major & 0xfff) << 8) | ((minor & ^0xff) << 12) | ((major & ^0xfff) << 32))

	return strace_types.ConstArg(syzType, dir, uint64(id))

}

func parse_HtonsHtonl(syzType prog.Type, dir prog.Dir, straceType *strace_types.Call, ctx *Context) prog.Arg {
	if len(straceType.Args) > 1 {
		panic("Parsing Htons/Htonl...it has more than one arg.")
	}
	switch typ := syzType.(type) {
	case *prog.ProcType:
		switch a := straceType.Args[0].(type) {
		case *strace_types.Expression:
			val := a.Eval(ctx.Target)
			if val >= typ.ValuesPerProc {
				return strace_types.ConstArg(syzType, dir, typ.ValuesPerProc-1)
			} else {
				return strace_types.ConstArg(syzType, dir, val)
			}
		default:
			panic("First arg of Htons/Htonl is not expression")
		}
	case *prog.ConstType, *prog.IntType, *prog.FlagsType:
		switch a := straceType.Args[0].(type) {
		case *strace_types.Expression:
			val := a.Eval(ctx.Target)
			return prog.MakeConstArg(syzType, dir, val)
		default:
			panic("First arg of Htons/Htonl is not expression")
		}
	default:
		Failf("First arg of Htons/Htonl is not const Type: %s\n", syzType.Name())
	}
	return nil
}

func parse_InetAddr(syzType prog.Type, dir prog.Dir, straceType *strace_types.Call, ctx *Context) prog.Arg {
	unionType := syzType.(*prog.UnionType)
	var idx int
	var inner_arg prog.Arg
	if len(straceType.Args) > 1 {
		panic("Parsing InetAddr...it has more than one arg.")
	}
	switch a := straceType.Args[0].(type) {
	case *strace_types.IpType:
		switch a.Str {
		case "0.0.0.0":
			idx = 0
		case "127.0.0.1":
			idx = 3
		case "255.255.255.255":
			idx = 6
		default:
			idx = 7
		}
		inner_arg = unionType.Fields[idx].DefaultArg(unionType.Fields[idx].Dir(dir))
	default:
		panic("Parsing inet_addr and inner arg has non ipv4 type")
	}
	return strace_types.UnionArg(syzType, dir, inner_arg, idx)
}

func parse_InetPton(syzType prog.Type, dir prog.Dir, straceType *strace_types.Call, ctx *Context) prog.Arg {
	unionType := syzType.(*prog.UnionType)
	var idx int
	var inner_arg prog.Arg
	if len(straceType.Args) != 3 {
		Failf("InetPton expects 3 args: %v.", straceType.Args)
	}
	switch a := straceType.Args[1].(type) {
	case *strace_types.IpType:
		switch a.Str {
		case "::":
			idx = 0
		case "::1":
			idx = 3
		default:
			idx = 0
		}
		inner_arg = unionType.Fields[idx].DefaultArg(unionType.Fields[idx].Dir(dir))
	default:
		panic("Parsing inet_addr and inner arg has non ipv4 type")
	}
	return strace_types.UnionArg(syzType, dir, inner_arg, idx)
}

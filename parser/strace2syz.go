package parser

import (
	"encoding/binary"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/shankarapailoor/moonshine/distiller"
	. "github.com/shankarapailoor/moonshine/logging"
	"github.com/shankarapailoor/moonshine/strace_types"
	"github.com/shankarapailoor/moonshine/tracker"
	"math/rand"
	"strings"
	//"bytes"

	"bytes"
)

type returnCache map[ResourceDescription]prog.Arg

func NewRCache() returnCache {
	return make(map[ResourceDescription]prog.Arg, 0)
}

func (r *returnCache) Cache(SyzType prog.Type, StraceType strace_types.Type, arg prog.Arg) {
	resDesc := ResourceDescription{
		Type: strace_types.GetSyzType(SyzType),
		Val:  StraceType.String(),
	}
	(*r)[resDesc] = arg
}

func (r *returnCache) Get(SyzType prog.Type, StraceType strace_types.Type) prog.Arg {
	resDesc := ResourceDescription{
		Type: strace_types.GetSyzType(SyzType),
		Val:  StraceType.String(),
	}
	if arg, ok := (*r)[resDesc]; ok {
		if arg != nil {
			return arg
		}
	}

	return nil
}

type ResourceDescription struct {
	Type string
	Val  string
}

type Context struct {
	Cache             returnCache
	Prog              *prog.Prog
	CurrentStraceCall *strace_types.Syscall
	CurrentSyzCall    *prog.Call
	CurrentStraceArg  strace_types.Type
	State             *tracker.State
	Target            *prog.Target
	CallToCover       map[*prog.Call][]uint64
	DependsOn         map[*prog.Call]map[*prog.Call]int
	// Builder replaces the removed (*prog.Target).AssignSizesCall. Its Append
	// runs assignSizesCall + neutralize on a call; we use it purely for those
	// side effects while keeping ctx.Prog as the program under construction
	// (the parser needs ctx.Prog.Calls indices while it is still parsing).
	Builder *prog.Builder
}

func NewContext(target *prog.Target) (ctx *Context) {
	ctx = &Context{}
	ctx.Cache = NewRCache()
	ctx.CurrentStraceCall = nil
	ctx.State = tracker.NewState(target)
	ctx.CurrentStraceArg = nil
	ctx.Target = target
	ctx.CallToCover = make(map[*prog.Call][]uint64)
	ctx.DependsOn = make(map[*prog.Call]map[*prog.Call]int, 0)
	ctx.Builder = prog.MakeProgGen(target)
	return
}

func (ctx *Context) GenerateSeeds() distiller.Seeds {
	var seeds distiller.Seeds = make([]*distiller.Seed, 0)
	for i, call := range ctx.Prog.Calls {
		var dependsOn map[*prog.Call]int = nil
		if _, ok := ctx.DependsOn[call]; ok {
			dependsOn = ctx.DependsOn[call]
		}
		seeds.Add(distiller.NewSeed(call,
			ctx.State,
			dependsOn,
			ctx.Prog,
			i,
			ctx.CallToCover[call]))
	}
	return seeds
}

func GetProgs(ctxs []*Context) []*prog.Prog {
	progs := make([]*prog.Prog, 0)
	for _, ctx := range ctxs {
		progs = append(progs, ctx.Prog)
	}
	return progs
}

func (ctx *Context) FillOutMemory() bool {
	if err := ctx.State.Tracker.FillOutMemory(ctx.Prog); err != nil {
		return false
	} else {
		totalMemory := ctx.State.Tracker.GetTotalMemoryAllocations(ctx.Prog)
		if totalMemory == 0 {
			fmt.Printf("length of zero mem prog: %d\n", totalMemory)
		} else {
			ctx.Prog.Calls = append([]*prog.Call{tracker.MakeMmap(ctx.Target, 0, uint64(totalMemory))}, ctx.Prog.Calls...)
		}
		if err := ValidateProg(ctx.Target, ctx.Prog); err != nil {
			panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
		}
	}
	return true
}

func ParseProg(trace *strace_types.Trace, target *prog.Target) (*Context, error) {
	syzProg := new(prog.Prog)
	syzProg.Target = target
	ctx := NewContext(target)
	ctx.Prog = syzProg
	for _, s_call := range trace.Calls {
		ctx.CurrentStraceCall = s_call
		if _, ok := strace_types.Unsupported[s_call.CallName]; ok {
			log.Logf(2, "Skipping unsupported: %s", s_call.CallName)
			continue
		}
		if s_call.Paused {
			/*Probably a case where the call was killed by a signal like the following
			2179  wait4(2180,  <unfinished ...>
			2179  <... wait4 resumed> 0x7fff28981bf8, 0, NULL) = ? ERESTARTSYS
			2179  --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER, si_pid=2180, si_uid=0} ---
			*/
			continue
		}
		ctx.CurrentStraceCall = s_call

		if shouldSkip(ctx) {
			continue
		}
		if call, err := parseCall(ctx); err == nil {
			if call == nil {
				log.Logf(2, "Call is nil: %s", s_call.CallName)
				continue
			}
			ctx.CallToCover[call] = s_call.Cover
			ctx.State.Analyze(call)
			if err := ctx.Builder.Append(call); err != nil {
				Failf("Failed to assign sizes for call: %s: %s\n", s_call.CallName, err.Error())
			}
			syzProg.Calls = append(syzProg.Calls, call)
		} else {
			Failf("Failed to parse call: %s\n", s_call.CallName)
		}
	}
	return ctx, nil
}

func parseCall(ctx *Context) (*prog.Call, error) {
	straceCall := ctx.CurrentStraceCall
	syzCallDef := ctx.Target.SyscallMap[straceCall.CallName]
	retCall := new(prog.Call)
	retCall.Meta = syzCallDef
	ctx.CurrentSyzCall = retCall

	Preprocess(ctx)
	if ctx.CurrentSyzCall.Meta == nil {
		//A call like fcntl may have variants like fcntl$get_flag
		//but no generic fcntl system call in Syzkaller
		return nil, nil
	}
	retCall.Ret = strace_types.ReturnArg(ctx.CurrentSyzCall.Meta.Ret)

	if call := ParseMemoryCall(ctx); call != nil {
		return call, nil
	}
	for i := range retCall.Meta.Args {
		var strArg strace_types.Type = nil
		if i < len(straceCall.Args) {
			strArg = straceCall.Args[i]
		}
		if arg, err := parseArgs(retCall.Meta.Args[i].Type, retCall.Meta.Args[i].Dir(prog.DirIn), strArg, ctx); err != nil {
			Failf("Failed to parse arg: %s\n", err.Error())
		} else {
			retCall.Args = append(retCall.Args, arg)
		}
		//arg := syzCall.Args[i]
	}
	parseResult(retCall.Meta.Ret, straceCall.Ret, ctx)

	return retCall, nil
}

func parseResult(syzType prog.Type, straceRet int64, ctx *Context) {
	if straceRet > 0 {
		//TODO: This is a hack NEED to refacto lexer to parser return values into strace types
		straceExpr := strace_types.NewExpression(strace_types.NewIntsType([]int64{straceRet}))
		switch syzType.(type) {
		case *prog.ResourceType:
			ctx.Cache.Cache(syzType, straceExpr, ctx.CurrentSyzCall.Ret)
		}
	}
}

func parseArgs(syzType prog.Type, dir prog.Dir, straceArg strace_types.Type, ctx *Context) (prog.Arg, error) {
	if straceArg == nil {
		return GenDefaultArg(syzType, dir, ctx), nil
	} else {
		ctx.CurrentStraceArg = straceArg
	}
	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.CsumType:
		return Parse_ConstType(a, dir, straceArg, ctx)
	case *prog.LenType:
		return GenDefaultArg(syzType, dir, ctx), nil
	case *prog.ProcType:
		return Parse_ProcType(a, dir, straceArg, ctx)
	case *prog.ResourceType:
		return Parse_ResourceType(a, dir, straceArg, ctx)
	case *prog.PtrType:
		return Parse_PtrType(a, dir, straceArg, ctx)
	case *prog.BufferType:
		return Parse_BufferType(a, dir, straceArg, ctx)
	case *prog.StructType:
		return Parse_StructType(a, dir, straceArg, ctx)
	case *prog.ArrayType:
		return Parse_ArrayType(a, dir, straceArg, ctx)
	case *prog.UnionType:
		return Parse_UnionType(a, dir, straceArg, ctx)
	case *prog.VmaType:
		return Parse_VmaType(a, dir, straceArg, ctx)
	default:
		panic(fmt.Sprintf("Unsupported  Type: %v\n", syzType))
	}
}

func Parse_VmaType(syzType *prog.VmaType, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	npages := uint64(1)
	// TODO: strace doesn't give complete info, need to guess random page range
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = uint64(int(syzType.RangeEnd)) // + r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
	}
	arg := strace_types.PointerArg(syzType, dir, 0, npages, nil)
	ctx.State.Tracker.AddAllocation(ctx.CurrentSyzCall, pageSize, arg)
	return arg, nil
}

func Parse_ArrayType(syzType *prog.ArrayType, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	args := make([]prog.Arg, 0)
	switch a := straceType.(type) {
	case *strace_types.ArrayType:
		if dir == prog.DirOut {
			return GenDefaultArg(syzType, dir, ctx), nil
		}
		for i := 0; i < a.Len; i++ {
			if arg, err := parseArgs(syzType.Elem, dir, a.Elems[i], ctx); err == nil {
				args = append(args, arg)
			} else {
				Failf("Error parsing array elem: %s\n", err.Error())
			}
		}
	case *strace_types.Field:
		return Parse_ArrayType(syzType, dir, a.Val, ctx)
	case *strace_types.PointerType, *strace_types.Expression, *strace_types.BufferType:
		return GenDefaultArg(syzType, dir, ctx), nil
	default:
		Failf("Error parsing Array: %s with Wrong Type: %s\n", syzType.TypeName, straceType.Name())
	}
	return strace_types.GroupArg(syzType, dir, args), nil
}

func Parse_StructType(syzType *prog.StructType, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	straceType = PreprocessStruct(syzType, straceType, ctx)
	args := make([]prog.Arg, 0)
	switch a := straceType.(type) {
	case *strace_types.StructType:
		reorderStructFields(syzType, a, ctx)
		args = append(args, evalFields(syzType.Fields, dir, a.Fields, ctx)...)
	case *strace_types.ArrayType:
		//Syzkaller's pipe definition expects a pipefd struct
		//But strace returns an array type
		args = append(args, evalFields(syzType.Fields, dir, a.Elems, ctx)...)
	case *strace_types.Field:
		if arg, err := parseArgs(syzType, dir, a.Val, ctx); err == nil {
			return arg, nil
		} else {
			Failf("Error parsing struct field: %#v", ctx)
		}
	case *strace_types.Call:
		args = append(args, ParseInnerCall(syzType, dir, a, ctx))
	case *strace_types.Expression:
		/*
		 May get here through select. E.g. select(2, [6, 7], ..) since Expression can
		 be Ints. However, creating fd set is hard and we let default arg through
		*/
		return GenDefaultArg(syzType, dir, ctx), nil
	case *strace_types.BufferType:
		return serialize(syzType, dir, []byte(a.Val), ctx)
	default:
		Failf("Unsupported Strace Type: %#v to Struct Type", a)
	}
	return strace_types.GroupArg(syzType, dir, args), nil
}

func evalFields(syzFields []prog.Field, dir prog.Dir, straceFields []strace_types.Type, ctx *Context) []prog.Arg {
	args := make([]prog.Arg, 0)
	j := 0
	for i, _ := range syzFields {
		fldDir := syzFields[i].Dir(dir)
		if prog.IsPad(syzFields[i].Type) {
			args = append(args, syzFields[i].DefaultArg(fldDir))
		} else {
			if j >= len(straceFields) {
				args = append(args, GenDefaultArg(syzFields[i].Type, fldDir, ctx))
			} else if arg, err := parseArgs(syzFields[i].Type, fldDir, straceFields[j], ctx); err == nil {
				args = append(args, arg)
			} else {
				Failf("Error parsing struct field: %#v", ctx)
			}
			j += 1
		}
	}
	return args
}

func Parse_UnionType(syzType *prog.UnionType, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch strType := straceType.(type) {
	case *strace_types.Field:
		switch strValType := strType.Val.(type) {
		case *strace_types.Call:
			return ParseInnerCall(syzType, dir, strValType, ctx), nil
		default:
			return Parse_UnionType(syzType, dir, strType.Val, ctx)
		}
	case *strace_types.Call:
		return ParseInnerCall(syzType, dir, strType, ctx), nil
	default:
		idx := IdentifyUnionType(ctx, syzType.TypeName)
		innerType := syzType.Fields[idx]
		if innerArg, err := parseArgs(innerType.Type, innerType.Dir(dir), straceType, ctx); err == nil {
			return strace_types.UnionArg(syzType, dir, innerArg, idx), nil
		} else {
			Failf("Error parsing union type: %#v", ctx)
		}
	}

	return nil, nil
}

func IdentifyUnionType(ctx *Context, typeName string) int {
	switch typeName {
	case "sockaddr_storage":
		return IdentifySockaddrStorageUnion(ctx)
	case "sockaddr_nl":
		return IdentifySockaddrNetlinkUnion(ctx)
	case "ifr_ifru":
		return IdentifyIfrIfruUnion(ctx)
	case "ifconf":
		return IdentifyIfconfUnion(ctx)
	case "bpf_instructions":
		return 0
	case "bpf_insn":
		return IdentifyBpfInsn(ctx)
	}
	return 0
}

func IdentifySockaddrStorageUnion(ctx *Context) int {
	call := ctx.CurrentStraceCall
	var straceArg strace_types.Type
	switch call.CallName {
	case "bind", "connect", "recvmsg", "sendmsg", "getsockname", "accept4", "accept":
		straceArg = call.Args[1]
	default:
		Failf("Trying to identify union for sockaddr_storage for call: %s\n", call.CallName)
	}
	switch strType := straceArg.(type) {
	case *strace_types.StructType:
		for i := range strType.Fields {
			fieldStr := strType.Fields[i].String()
			if strings.Contains(fieldStr, "AF_INET") {
				return 1
			} else if strings.Contains(fieldStr, "AF_INET6") {
				return 4
			} else if strings.Contains(fieldStr, "AF_UNIX") {
				return 0
			} else if strings.Contains(fieldStr, "AF_NETLINK") {
				return 5
			}
		}
	default:
		Failf("Failed to parse Sockaddr Stroage Union Type. Strace Type: %#v\n", strType)
	}
	return -1
}

func IdentifySockaddrNetlinkUnion(ctx *Context) int {
	switch a := ctx.CurrentStraceArg.(type) {
	case *strace_types.StructType:
		if len(a.Fields) > 2 {
			switch b := a.Fields[1].(type) {
			case *strace_types.Expression:
				pid := b.Eval(ctx.Target)
				if pid > 0 {
					//User
					return 0
				} else if pid == 0 {
					//Kernel
					return 1
				} else {
					//Unspec
					return 2
				}
			case *strace_types.Field:
				curArg := ctx.CurrentStraceArg
				ctx.CurrentStraceArg = b.Val
				idx := IdentifySockaddrNetlinkUnion(ctx)
				ctx.CurrentStraceArg = curArg
				return idx
			default:
				Failf("Parsing netlink addr struct and expect expression for first arg: %s\n", a.Name())
			}
		}
	}
	return 2
}

func IdentifyIfrIfruUnion(ctx *Context) int {
	switch ctx.CurrentStraceArg.(type) {
	case *strace_types.Expression:
		return 2
	case *strace_types.Field:
		return 2
	default:
		return 0
	}
}

func IdentifyIfconfUnion(ctx *Context) int {
	switch ctx.CurrentStraceArg.(type) {
	case *strace_types.StructType:
		return 1
	default:
		return 0
	}
}

func IdentifyBpfInsn(ctx *Context) int {
	return 1
}

func Parse_BufferType(syzType *prog.BufferType, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	if dir == prog.DirOut {
		if !syzType.Varlen() {
			return prog.MakeOutDataArg(syzType, dir, syzType.Size()), nil
		}
		switch a := straceType.(type) {
		case *strace_types.BufferType:
			return prog.MakeOutDataArg(syzType, dir, uint64(len(a.Val))), nil
		case *strace_types.Field:
			return Parse_BufferType(syzType, dir, a.Val, ctx)
		default:
			switch syzType.Kind {
			case prog.BufferBlobRand:
				size := rand.Intn(256)
				return prog.MakeOutDataArg(syzType, dir, uint64(size)), nil

			case prog.BufferBlobRange:
				max := rand.Intn(int(syzType.RangeEnd) - int(syzType.RangeBegin) + 1)
				size := max + int(syzType.RangeBegin)
				return prog.MakeOutDataArg(syzType, dir, uint64(size)), nil
			default:
				panic(fmt.Sprintf("unexpected buffer type kind: %v. call %v arg %v", syzType.Kind, ctx.CurrentSyzCall, straceType))
			}
		}
	}
	var bufVal []byte
	switch a := straceType.(type) {
	case *strace_types.BufferType:
		bufVal = []byte(a.Val)
	case *strace_types.Expression:
		val := a.Eval(ctx.Target)
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *strace_types.PointerType:
		val := a.Address
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *strace_types.StructType:
		return GenDefaultArg(syzType, dir, ctx), nil
	case *strace_types.Field:
		return parseArgs(syzType, dir, a.Val, ctx)
	default:
		Failf("Cannot parse type %#v for Buffer Type\n", straceType)
	}
	if !syzType.Varlen() {
		bufVal = strace_types.GenBuff(bufVal, syzType.Size())
		buf := make([]byte, syzType.Size())
		valLen := len(bufVal)
		for i := range buf {
			if i < valLen {
				buf[i] = bufVal[i]
			} else {
				buf[i] = 0
			}
		}
		bufVal = buf
	}
	return strace_types.DataArg(syzType, dir, bufVal), nil
}

func Parse_PtrType(syzType *prog.PtrType, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	switch a := straceType.(type) {
	case *strace_types.PointerType:
		if a.IsNull() {
			return syzType.DefaultArg(dir), nil
		} else {
			if a.Res == nil {
				res := GenDefaultArg(syzType.Elem, syzType.ElemDir, ctx)
				return addr(ctx, syzType, dir, res.Size(), res)
			}
			if res, err := parseArgs(syzType.Elem, syzType.ElemDir, a.Res, ctx); err != nil {
				panic(fmt.Sprintf("Error parsing Ptr: %s", err.Error()))
			} else {
				return addr(ctx, syzType, dir, res.Size(), res)
			}
		}
	case *strace_types.Expression:
		//Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := GenDefaultArg(syzType.Elem, syzType.ElemDir, ctx)
		return addr(ctx, syzType, dir, res.Size(), res)
	default:
		if res, err := parseArgs(syzType.Elem, syzType.ElemDir, a, ctx); err != nil {
			panic(fmt.Sprintf("Error parsing Ptr: %s", err.Error()))
		} else {
			return addr(ctx, syzType, dir, res.Size(), res)
		}
	}
}

func Parse_ConstType(syzType prog.Type, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	if dir == prog.DirOut {
		return syzType.DefaultArg(dir), nil
	}
	switch a := straceType.(type) {
	case *strace_types.Expression:
		if a.IntsType != nil && len(a.IntsType) >= 2 {
			/*
				 	May get here through select. E.g. select(2, [6, 7], ..) since Expression can
					 be Ints. However, creating fd set is hard and we let default arg through
			*/
			return GenDefaultArg(syzType, dir, ctx), nil
		}
		return strace_types.ConstArg(syzType, dir, a.Eval(ctx.Target)), nil
	case *strace_types.DynamicType:
		return strace_types.ConstArg(syzType, dir, a.BeforeCall.Eval(ctx.Target)), nil
	case *strace_types.ArrayType:
		/*
			Sometimes strace represents a pointer to int as [0] which gets parsed
			as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]).
		*/
		if a.Len == 0 {
			panic(fmt.Sprintf("Parsing const type. Got array type with len 0: %#v", ctx))
		}
		return Parse_ConstType(syzType, dir, a.Elems[0], ctx)
	case *strace_types.StructType:
		/*
			Sometimes system calls have an int type that is actually a union. Strace will represent the union
			like a struct e.g.
			sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
			For now we choose the first option
		*/
		return Parse_ConstType(syzType, dir, a.Fields[0], ctx)
	case *strace_types.Field:
		//We have an argument of the form sin_port=IntType(0)
		return parseArgs(syzType, dir, a.Val, ctx)
	case *strace_types.Call:
		//We have likely hit a call like inet_pton, htonl, etc
		return ParseInnerCall(syzType, dir, a, ctx), nil
	case *strace_types.BufferType:
		//The call almost certainly an error or missing fields
		return GenDefaultArg(syzType, dir, ctx), nil
		//E.g. ltp_bind01 two arguments are empty and
	case *strace_types.PointerType:
		/*
			This can be triggered by the following:
			2435  connect(3, {sa_family=0x2f ,..., 16)*/
		return strace_types.ConstArg(syzType, dir, a.Address), nil
	default:
		Failf("Cannot convert Strace Type: %s to Const Type", straceType.Name())
	}
	return nil, nil
}

func Parse_ResourceType(syzType *prog.ResourceType, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	if dir == prog.DirOut {
		res := strace_types.ResultArg(syzType, dir, nil, syzType.Default())
		ctx.Cache.Cache(syzType, straceType, res)
		return res, nil
	}
	switch a := straceType.(type) {
	case *strace_types.Expression:
		val := a.Eval(ctx.Target)
		if arg := ctx.Cache.Get(syzType, straceType); arg != nil {
			res := strace_types.ResultArg(arg.Type(), dir, arg.(*prog.ResultArg), strace_types.DefaultValue(arg.Type()))
			return res, nil
		}
		res := strace_types.ResultArg(syzType, dir, nil, val)
		return res, nil
	case *strace_types.Field:
		return Parse_ResourceType(syzType, dir, a.Val, ctx)
	default:
		panic("Resource Type only supports Expression")
	}
}

func Parse_ProcType(syzType *prog.ProcType, dir prog.Dir, straceType strace_types.Type, ctx *Context) (prog.Arg, error) {
	if dir == prog.DirOut {
		return GenDefaultArg(syzType, dir, ctx), nil
	}
	switch a := straceType.(type) {
	case *strace_types.Expression:
		val := a.Eval(ctx.Target)
		if val >= syzType.ValuesPerProc {
			return strace_types.ConstArg(syzType, dir, syzType.ValuesPerProc-1), nil
		} else {
			return strace_types.ConstArg(syzType, dir, val), nil
		}
	case *strace_types.Field:
		return parseArgs(syzType, dir, a.Val, ctx)
	case *strace_types.Call:
		return ParseInnerCall(syzType, dir, a, ctx), nil
	case *strace_types.BufferType:
		/* Again probably an error case
		   Something like the following will trigger this
		    bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
		*/
		return GenDefaultArg(syzType, dir, ctx), nil
	default:
		Failf("Unsupported Type for Proc: %#v\n", straceType)
	}
	return nil, nil
}

func GenDefaultArg(syzType prog.Type, dir prog.Dir, ctx *Context) prog.Arg {
	switch a := syzType.(type) {
	case *prog.PtrType:
		res := a.Elem.DefaultArg(a.ElemDir)
		ptr, _ := addr(ctx, syzType, dir, res.Size(), res)
		return ptr
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.ProcType, *prog.CsumType:
		return syzType.DefaultArg(dir)
	case *prog.BufferType:
		return a.DefaultArg(dir)
	case *prog.StructType:
		var inner []prog.Arg
		for _, field := range a.Fields {
			inner = append(inner, GenDefaultArg(field.Type, field.Dir(dir), ctx))
		}
		return strace_types.GroupArg(a, dir, inner)
	case *prog.UnionType:
		opt := a.Fields[0]
		return strace_types.UnionArg(a, dir, GenDefaultArg(opt.Type, opt.Dir(dir), ctx), 0)
	case *prog.ArrayType:
		return syzType.DefaultArg(dir)
	case *prog.ResourceType:
		return prog.MakeResultArg(syzType, dir, nil, a.Default())
	case *prog.VmaType:
		return syzType.DefaultArg(dir)
	default:
		panic(fmt.Sprintf("Unsupported Type: %#v", syzType))
	}
}

func serialize(syzType prog.Type, dir prog.Dir, buf []byte, ctx *Context) (prog.Arg, error) {
	fmt.Printf("Serializing object of size: %d: %s: %d\n", syzType.Size(), syzType.Name(), len(buf))
	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.CsumType:
		return strace_types.ConstArg(a, dir, bufToUint(buf[:syzType.Size()])), nil
	case *prog.ProcType:
		return GenDefaultArg(syzType, dir, ctx), nil
	case *prog.PtrType:
		if res, err := serialize(a.Elem, a.ElemDir, buf, ctx); err == nil {
			return addr(ctx, a, dir, res.Size(), res)
		}
		panic("Failed to serialize pointer type")
	case *prog.StructType:
		pos := uint64(0)
		bufLen := uint64(len(buf))
		args := make([]prog.Arg, 0)
		for _, field := range a.Fields {
			fldDir := field.Dir(dir)
			if pos+field.Size() >= bufLen {
				args = append(args, GenDefaultArg(field.Type, fldDir, ctx))
				continue
			} else {
				if res, err := serialize(field.Type, fldDir, buf[pos:pos+field.Size()], ctx); err == nil {
					args = append(args, res)
				} else {
					panic("Failed to serialize struct field")
				}
			}
			pos += field.Size()
		}
		return strace_types.GroupArg(syzType, dir, args), nil
	default:
		panic("Unsupported Type\n")
	}
}

func bufToUint(buf []byte) uint64 {
	switch len(buf) {
	case 1:
		return uint64(buf[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(buf))
	case 4:
		return uint64(binary.LittleEndian.Uint32(buf))
	case 8:
		return binary.LittleEndian.Uint64(buf)
	default:
		panic("Failed to convert byte to int")
	}
}

func addr(ctx *Context, syzType prog.Type, dir prog.Dir, size uint64, data prog.Arg) (prog.Arg, error) {
	arg := strace_types.PointerArg(syzType, dir, uint64(0), 0, data)
	ctx.State.Tracker.AddAllocation(ctx.CurrentSyzCall, size, arg)
	return arg, nil
}

func reorderStructFields(syzType *prog.StructType, straceType *strace_types.StructType, ctx *Context) {
	/*
		Sometimes strace reports struct fields out of order compared to Syzkaller.
		Example: 5704  bind(3, {sa_family=AF_INET6,
					sin6_port=htons(8888),
					inet_pton(AF_INET6, "::", &sin6_addr),
					sin6_flowinfo=htonl(2206138368),
					sin6_scope_id=2049825634}, 128) = 0
		The flow_info and pton fields are switched in Syzkaller
	*/
	switch syzType.TypeName {
	case "sockaddr_in6":
		field2 := straceType.Fields[2]
		straceType.Fields[2] = straceType.Fields[3]
		straceType.Fields[3] = field2
	case "bpf_insn_generic", "bpf_insn_exit", "bpf_insn_alu", "bpf_insn_jmp", "bpf_insn_ldst":
		fmt.Printf("bpf_insn_generic size: %d, typsize: %d\n", syzType.Size(), syzType.TypeSize)
		reg := (straceType.Fields[1].Eval(ctx.Target)) | (straceType.Fields[2].Eval(ctx.Target) << 4)
		newFields := make([]strace_types.Type, len(straceType.Fields)-1)
		newFields[0] = straceType.Fields[0]
		newFields[1] = strace_types.NewExpression(strace_types.NewIntType(int64(reg)))
		newFields[2] = straceType.Fields[3]
		newFields[3] = straceType.Fields[4]
		straceType.Fields = newFields
	}
	return
}

func GenDefaultStraceType(syzType prog.Type) strace_types.Type {
	switch a := syzType.(type) {
	case *prog.StructType:
		straceFields := make([]strace_types.Type, len(a.Fields))
		for i := 0; i < len(straceFields); i++ {
			straceFields[i] = GenDefaultStraceType(a.Fields[i].Type)
		}
		return strace_types.NewStructType(straceFields)
	case *prog.ArrayType:
		straceFields := make([]strace_types.Type, 1)
		straceFields[0] = GenDefaultStraceType(a.Elem)
		return strace_types.NewArrayType(straceFields)
	case *prog.ConstType, *prog.ProcType, *prog.LenType, *prog.FlagsType, *prog.IntType:
		return strace_types.NewExpression(strace_types.NewIntType(0))
	case *prog.PtrType:
		return strace_types.NewPointerType(0, GenDefaultStraceType(a.Elem))
	case *prog.UnionType:
		return GenDefaultStraceType(a.Fields[0].Type)
	default:
		Failf("Unsupported syz type for generating default strace type: %s\n", syzType.Name())
	}
	return nil
}

// ValidateProg replaces the removed (*prog.Prog).Validate. Validation in the
// modern prog package is unexported; the only supported entry point is
// prog.MakeProgGen + Builder.Finalize, which validates and then runs
// SerializeForExec. All arguments are reused as-is, only p.Calls is refreshed
// from the builder's program (same *prog.Call objects, same order).
func ValidateProg(target *prog.Target, p *prog.Prog) error {
	builder := prog.MakeProgGen(target)
	for _, call := range p.Calls {
		if err := builder.Append(call); err != nil {
			return err
		}
	}
	finalized, err := builder.Finalize()
	if err != nil {
		return err
	}
	p.Calls = finalized.Calls
	return nil
}

func SanitizeFilename(filename string) string {
	var buf bytes.Buffer
	splitStr := strings.Split(filename, `/`)

	if len(splitStr) >= 3 {
		if strings.Compare(splitStr[0], "") == 0 {
			if strings.Compare(splitStr[1], "tmp") == 0 {
				//We have a root file
				buf.WriteString(splitStr[1])
				buf.WriteString("-")
				buf.WriteString(splitStr[2])
				if len(splitStr) > 3 {
					buf.WriteString(`/`)
					for i := 3; i < len(splitStr)-1; i++ {
						buf.WriteString(splitStr[i])
					}
					buf.WriteString(splitStr[len(splitStr)-1])
				}
				return buf.String()
			}
		}
	}
	return filename
}

func shouldSkip(ctx *Context) bool {
	syscall := ctx.CurrentStraceCall
	switch syscall.CallName {
	case "write":
		switch a := syscall.Args[0].(type) {
		case *strace_types.Expression:
			val := a.Eval(ctx.Target)
			if val == 1 || val == 2 {
				return true
			}
		}
	}
	return false
}

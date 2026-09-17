package parser

import (
	"github.com/google/syzkaller/prog"
	"github.com/shankarapailoor/moonshine/strace_types"
)

type structHandler func(syzType *prog.StructType, straceType strace_types.Type, ctx *Context) strace_types.Type

var SpecialStruct_Map = map[string]structHandler{
	"bpf_framed_program": bpfFramedProgramHandler,
}

func PreprocessStruct(syzType *prog.StructType, straceType strace_types.Type, ctx *Context) strace_types.Type {
	if structFunc, ok := SpecialStruct_Map[syzType.Name()]; ok {
		return structFunc(syzType, straceType, ctx)
	}
	return straceType
}

func bpfFramedProgramHandler(syzType *prog.StructType, straceType strace_types.Type, ctx *Context) strace_types.Type {
	switch a := straceType.(type) {
	case *strace_types.ArrayType:
		straceStructArgs := make([]strace_types.Type, len(syzType.Fields))
		arrType := a
		straceStructArgs[1] = arrType
		straceArg0 := GenDefaultStraceType(syzType.Fields[0].Type)
		straceStructArgs[0] = straceArg0
		straceStructArgs = append(straceStructArgs, GenDefaultStraceType(syzType.Fields[1].Type))
		return strace_types.NewStructType(straceStructArgs)
	}
	return straceType
}

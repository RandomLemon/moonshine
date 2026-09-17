package tracker

import (
	"github.com/google/syzkaller/prog"
)

// The 2018 prog package exposed ResultArg.Set(map[*ResultArg]bool) and
// ResultArg.Uses() to read/write the "arguments that use this result" set, and
// Prog.StripDependencies to drop all result references. Both are gone in the
// modern API: the set is unexported and is maintained exclusively by
// prog.MakeResultArg (and prog.clone). Modern prog/validation.go also demands
// that every entry in that set still be part of the program being validated, so
// merely clearing Res (or leaving the set alone after dropping calls) makes the
// program fail validation with "use of ... refers to an out-of-tree arg".
//
// The distillers used to mutate that set directly: TrackDependencies and
// isDependent cleared it, BuildDependency re-added exactly the dependencies that
// belong to the distilled program, and RandomDistiller dropped all of them. Both
// effects are reproduced here by rebuilding the argument trees, which is the only
// consistent expression available: a rebuilt arg carries no stale entries, and
// re-linking goes through MakeResultArg, which maintains the set correctly.

// StripDependencies replaces (*prog.Prog).StripDependencies: it drops every
// result reference so the program is self-contained.
func StripDependencies(p *prog.Prog) {
	for _, call := range p.Calls {
		if call.Meta.Ret != nil {
			call.Ret = prog.MakeReturnArg(call.Meta.Ret)
		}
		for i, arg := range call.Args {
			call.Args[i] = rebuildArg(arg, nil)
		}
	}
}

// RelinkDependencies rebuilds every argument in p so that result references
// point only at return values of calls that are actually present in p, and so
// that the (unexported) back-reference sets mention exactly those arguments.
// Dependencies on calls outside p are dropped, matching what
// TrackDependencies/BuildDependency used to produce for a distilled program.
func RelinkDependencies(p *prog.Prog) {
	producers := make(map[*prog.ResultArg]*prog.ResultArg)
	for _, call := range p.Calls {
		if call.Meta.Ret == nil {
			continue
		}
		ret := prog.MakeReturnArg(call.Meta.Ret)
		if call.Ret != nil {
			producers[call.Ret] = ret
		}
		call.Ret = ret
	}
	for _, call := range p.Calls {
		for i, arg := range call.Args {
			call.Args[i] = rebuildArg(arg, producers)
		}
	}
}

// rebuildArg deep-copies arg. When producers is nil every result reference is
// dropped; otherwise a reference is kept if its producer is a call of the
// program being rebuilt. Addresses and values already assigned by
// MemoryTracker.FillOutMemory are preserved.
func rebuildArg(arg prog.Arg, producers map[*prog.ResultArg]*prog.ResultArg) prog.Arg {
	switch a := arg.(type) {
	case *prog.ConstArg:
		return prog.MakeConstArg(a.Type(), a.Dir(), a.Val)
	case *prog.ResultArg:
		var res *prog.ResultArg
		if producers != nil && a.Res != nil {
			res = producers[a.Res]
		}
		r := prog.MakeResultArg(a.Type(), a.Dir(), res, a.Val)
		r.OpDiv = a.OpDiv
		r.OpAdd = a.OpAdd
		return r
	case *prog.PointerArg:
		if a.Res == nil {
			return prog.MakeVmaPointerArg(a.Type(), a.Dir(), a.Address, a.VmaSize)
		}
		return prog.MakePointerArg(a.Type(), a.Dir(), a.Address, rebuildArg(a.Res, producers))
	case *prog.DataArg:
		if a.Dir() == prog.DirOut {
			return prog.MakeOutDataArg(a.Type(), a.Dir(), a.Size())
		}
		return prog.MakeDataArg(a.Type(), a.Dir(), a.Data())
	case *prog.GroupArg:
		inner := make([]prog.Arg, len(a.Inner))
		for i, arg := range a.Inner {
			inner[i] = rebuildArg(arg, producers)
		}
		return prog.MakeGroupArg(a.Type(), a.Dir(), inner)
	case *prog.UnionArg:
		return prog.MakeUnionArg(a.Type(), a.Dir(), rebuildArg(a.Option, producers), a.Index)
	default:
		panic("unsupported arg type")
	}
}

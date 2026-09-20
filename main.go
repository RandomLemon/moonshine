package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/shankarapailoor/moonshine/configs"
	"github.com/shankarapailoor/moonshine/distiller"
	. "github.com/shankarapailoor/moonshine/logging"
	. "github.com/shankarapailoor/moonshine/parser"
	. "github.com/shankarapailoor/moonshine/scanner"
	"github.com/shankarapailoor/moonshine/strace_types"
	"github.com/shankarapailoor/moonshine/tracker"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	flagFile    = flag.String("file", "", "file to parse")
	flagDir     = flag.String("dir", "", "director to parse")
	flagDistill = flag.String("distill", "", "Path to distillation config")
)

const (
	OS               = "linux"
	Arch             = "amd64"
	currentDBVersion = 3
)

func main() {
	rev := prog.GitRevision
	flag.Parse()
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		Failf("error getting target: %v, git revision: %v", err.Error(), rev)
	} else {
		BuildIoctlVariants(target)
		ParseTraces(target)
		pack("deserialized", "corpus.db")
	}
}

func progIsTooLarge(prog_ *prog.Prog) bool {
	// SerializeForExec no longer takes a caller-provided buffer: it allocates
	// its own and enforces prog.ExecBufferSize internally.
	if _, err := prog_.SerializeForExec(); err != nil {
		return true
	}
	return false
}

func ParseTraces(target *prog.Target) []*Context {
	ret := make([]*Context, 0)
	names := make([]string, 0)
	distill := false
	if *flagFile != "" {
		names = append(names, *flagFile)
	} else if *flagDir != "" {
		names = getFileNames(*flagDir)
	} else {
		panic("Flag or FlagDir required")
	}

	if *flagDistill != "" {
		distill = true
	}
	seeds := make(distiller.Seeds, 0)
	totalFiles := len(names)
	// Programs are written into deserialized/; create it so a fresh checkout
	// works without a manual mkdir.
	if err := os.MkdirAll("deserialized", 0755); err != nil {
		Failf("failed to create deserialized dir: %v", err)
	}

	fmt.Printf("Total Number of Files: %d\n", totalFiles)
	for i, file := range names {
		fmt.Printf("Parsing File %d/%d: %s\n", i+1, totalFiles, path.Base(names[i]))
		tree := Parse(file)
		if tree == nil {
			fmt.Fprintf(os.Stderr, "File: %s is empty\n", path.Base(file))
			continue
		}
		ctxs := ParseTree(tree, tree.RootPid, target)
		log.Logf(2, "Context size: %d", len(ctxs))
		ret = append(ret, ctxs...)
		i := 0
		for _, ctx := range ctxs {
			ctx.Prog.Target = ctx.Target
			if !distill {
				if err := FillOutMemory(ctx.Prog, ctx.State.Tracker); err != nil {
					log.Logf(2, "Failed to fill out memory: %s", err)
					continue
				}
				if progIsTooLarge(ctx.Prog) {
					fmt.Fprintln(os.Stderr, "Prog is too large")
					continue
				}
				i += 1
				s_name := "deserialized/" + filepath.Base(file) + strconv.Itoa(i)
				if err := os.WriteFile(s_name, ctx.Prog.Serialize(), 0640); err != nil {
					Failf("failed to output file: %v", err)
				}
			} else {
				newSeeds := ctx.GenerateSeeds()
				for _, seed := range newSeeds {
					seeds.Add(seed)
				}
			}
		}

	}
	if distill {
		fmt.Fprintf(os.Stderr, "Total number of seeds: %d\n", seeds.Len())
		distler := distiller.NewDistiller(config.NewDistillConfig(*flagDistill))
		distler.Add(seeds)
		distilledProgs := distler.Distill(GetProgs(ret))
		log.Logf(2, "Distilled Progs: %d", len(distilledProgs))
		for i, prog_ := range distilledProgs {
			if progIsTooLarge(prog_) {
				fmt.Fprintln(os.Stderr, "Prog is too large")
				continue
			}
			if err := ValidateProg(prog_.Target, prog_); err != nil {
				panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
			}
			s_name := "deserialized/" + "distill" + strconv.Itoa(i)
			if err := os.WriteFile(s_name, prog_.Serialize(), 0640); err != nil {
				Failf("failed to output file: %v", err)
			}
		}
	}
	return ret
}

func getFileNames(dir string) []string {
	names := make([]string, 0)
	if infos, err := os.ReadDir(dir); err == nil {
		for _, info := range infos {
			name := path.Join(dir, info.Name())
			names = append(names, name)
		}
	} else {
		Failf("Failed to read dir: %s\n", err.Error())
	}
	return names
}

func ParseTree(tree *strace_types.TraceTree, pid int64, target *prog.Target) []*Context {
	ctxs := make([]*Context, 0)
	ctx, err := ParseProg(tree.TraceMap[pid], target)
	parsedProg := ctx.Prog
	if err != nil {
		panic("Failed to parse program")
	}

	if len(parsedProg.Calls) == 0 {
		parsedProg = nil
	}

	if parsedProg != nil {
		ctx.Prog = parsedProg
		ctxs = append(ctxs, ctx)
	}
	for _, pid_ := range tree.Ptree[pid] {
		if tree.TraceMap[pid_] != nil {
			ctxs = append(ctxs, ParseTree(tree, pid_, target)...)
		}
	}
	return ctxs
}

func FillOutMemory(prog_ *prog.Prog, tracker_ *tracker.MemoryTracker) error {
	if err := tracker_.FillOutMemory(prog_); err != nil {
		return err
	} else {
		totalMemory := tracker_.GetTotalMemoryAllocations(prog_)
		if totalMemory == 0 {
			fmt.Printf("length of zero mem prog: %d\n", totalMemory)
		} else {
			calls := make([]*prog.Call, 0)
			calls = append(append(calls, tracker.MakeMmap(prog_.Target, 0, uint64(totalMemory))), prog_.Calls...)
			prog_.Calls = calls
		}
		if err := ValidateProg(prog_.Target, prog_); err != nil {
			panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
		}
	}
	return nil
}

func pack(dir, file string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		Failf("failed to read dir: %v", err)
	}
	os.Remove(file)
	db, err := db.Open(file, false)
	db.BumpVersion(currentDBVersion)
	if err != nil {
		Failf("failed to open database file: %v", err)
	}
	fmt.Println("Deserializing programs => deserialized/")
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			Failf("failed to read file %v: %v", file.Name(), err)
		}
		var seq uint64
		key := file.Name()
		if parts := strings.Split(file.Name(), "-"); len(parts) == 2 {
			var err error

			if seq, err = strconv.ParseUint(parts[1], 10, 64); err == nil {
				key = parts[0]
			}
		}
		if sig := hash.String(data); key != sig {
			key = sig
		}
		db.Save(key, data, seq)
	}
	if err := db.Flush(); err != nil {
		Failf("failed to save database file: %v", err)
	}
}

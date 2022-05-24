// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// mutates mutates a given program and prints result.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS     = flag.String("os", runtime.GOOS, "target os")
	flagArch   = flag.String("arch", runtime.GOARCH, "target arch")
	flagPoc    = flag.String("poc", "", "poc")
	flagLen    = flag.Int("len", prog.RecommendedCalls, "number of calls in programs")
	flagEnable = flag.String("enable", "", "comma-separated list of enabled syscalls")
)

type mutationTypes struct {
	target      *prog.Target
	prioSum     float64
	args        []mutationType
	similarArgs []mutationType
	argsBuffer  [16]mutationType
}

type mutationType struct {
	arg      prog.Arg
	ctx      prog.ArgCtx
	priority float64
	prio     float64
}

func (mt *mutationTypes) collectTypes(arg prog.Arg, ctx *prog.ArgCtx) {
	pValue := float64(0)
	switch typ := arg.Type().(type) {
	case *prog.StructType:
		for _, field := range typ.Fields {
			switch field.Type.(type) {
			case *prog.StructType:
			case *prog.UnionType:
			case *prog.ConstType:
			case *prog.CsumType:
			case *prog.ResourceType:
			default:
				pValue += float64(3)
			}
		}
		mt.prioSum += pValue
		mt.args = append(mt.args, mutationType{arg, *ctx, mt.prioSum, pValue})

	case *prog.UnionType:
		mt.prioSum += float64(4)
		mt.args = append(mt.args, mutationType{arg, *ctx, mt.prioSum, pValue})
	}
}

func (mt *mutationTypes) chooseType(r *rand.Rand) (prog.Arg, prog.ArgCtx, int) {
	goal := mt.prioSum * r.Float64()
	chosenIdx := sort.Search(len(mt.args), func(i int) bool { return mt.args[i].priority >= goal })
	arg := mt.args[chosenIdx]
	return arg.arg, arg.ctx, chosenIdx
}

func replaceArg(arg, arg1 prog.Arg) {
	if arg == arg1 {
		panic("same arg")
	}
	fmt.Printf("\nReplacing\n%s\nwith\n%s\n", arg, arg1)
	switch a := arg.(type) {
	case *prog.ConstArg:
		*a = *arg1.(*prog.ConstArg)
	case *prog.ResultArg:
		// replaceResultArg(a, arg1.(*prog.ResultArg))
	case *prog.PointerArg:
		*a = *arg1.(*prog.PointerArg)
	case *prog.UnionArg:
		*a = *arg1.(*prog.UnionArg)
	case *prog.DataArg:
		*a = *arg1.(*prog.DataArg)
	case *prog.GroupArg:
		a1 := arg1.(*prog.GroupArg)
		if len(a.Inner) != len(a1.Inner) {
			panic(fmt.Sprintf("replaceArg: group fields don't match: %v/%v",
				len(a.Inner), len(a1.Inner)))
		}
		a.ArgCommon = a1.ArgCommon
		for i := range a.Inner {
			replaceArg(a.Inner[i], a1.Inner[i])
		}
	default:
		panic(fmt.Sprintf("replaceArg: bad arg kind %#v", arg))
	}
}

func parseArg(p *prog.Prog) map[string]mutationTypes {
	argMap := make(map[string]mutationTypes)
	for _, c := range p.Calls {
		fmt.Printf("syscall: %s\n", c.Meta.Name)
		mt := &mutationTypes{target: p.Target, prioSum: float64(0)}
		prog.ForeachArg(c, mt.collectTypes)
		for _, aa := range mt.args {
			fmt.Printf("This is the arg: %s(%T): %s\n", aa.arg.Type().String(), aa.arg, aa.arg)
		}
		argMap[c.Meta.Name] = *mt
	}
	return argMap
}

func logArgMap(argMap map[string]mutationTypes) {
	for syscall, mt := range argMap {
		fmt.Printf("in syscall %s\n", syscall)
		for _, aa := range mt.args {
			fmt.Printf("This is the arg: %s(%T)\n", aa.arg.Type().String(), aa.arg)
		}
	}
}

func getSimilarTypes(a, b map[string]mutationTypes) map[string]*mutationTypes {
	sameArg := make(map[string]*mutationTypes)
	prioSum := float64(0)
	for syscallA, mtA := range a {
		for syscallB, mtB := range b {
			if syscallA == syscallB {
				Mts := &mutationTypes{}
				Mts.args = make([]mutationType, 0)
				Mts.similarArgs = make([]mutationType, 0)
				for _, argA := range mtA.args {
					for _, argB := range mtB.args {
						if argA.arg.Type().String() == argB.arg.Type().String() {
							fmt.Printf("Adding: %s\n", argA.arg.Type().String())
							prioSum += argA.prio
							Mts.args = append(Mts.args, mutationType{argA.arg, argA.ctx, prioSum, argA.prio})
							Mts.similarArgs = append(Mts.similarArgs, argB)
						}
					}
				}
				Mts.target = mtA.target
				Mts.prioSum = prioSum

				if len(Mts.args) == 0 {
					continue
				}

				sameArg[syscallA] = Mts
			}
		}
	}
	return sameArg
}

func main() {
	flag.Parse()

	if *flagPoc == "" {
		fmt.Printf("please specify the poc by -poc\n")
		os.Exit(1)
	}

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	seed := time.Now().UnixNano()
	rs := rand.NewSource(seed)
	r := rand.New(rs)

	var syscalls map[*prog.Syscall]bool
	if *flagEnable != "" {
		enabled := strings.Split(*flagEnable, ",")
		syscallsIDs, err := mgrconfig.ParseEnabledSyscalls(target, enabled, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse enabled syscalls: %v", err)
			os.Exit(1)
		}
		syscalls = make(map[*prog.Syscall]bool)
		for _, id := range syscallsIDs {
			syscalls[target.Syscalls[id]] = true
		}
		var disabled map[*prog.Syscall]string
		syscalls, disabled = target.TransitivelyEnabledCalls(syscalls)
		for c, reason := range disabled {
			fmt.Fprintf(os.Stderr, "disabling %v: %v\n", c.Name, reason)
		}
	}

	data, err := ioutil.ReadFile(*flagPoc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}

	poc, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}

	PocArgMaps := parseArg(poc)
	// logArgMap(PocArgMaps)

	var p *prog.Prog
	if flag.NArg() == 0 {
		fmt.Printf("please specify the input to be mutated\n")
		os.Exit(-1)
	} else {
		data, err := ioutil.ReadFile(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
			os.Exit(1)
		}
		p, err = target.Deserialize(data, prog.NonStrict)
		pOriginal := p.Clone()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Original input: %s\n", p.Serialize())
		SeedArgMaps := parseArg(p)
		// logArgMap(SeedArgMaps)

		SimilarArgMap := getSimilarTypes(SeedArgMaps, PocArgMaps)

		fmt.Printf("size of similar ArgMap : %v\n", len(SimilarArgMap))

		if len(SimilarArgMap) == 0 {
			fmt.Printf("Not similar inputs\n")
			return
		}

		// choose syscall
		sumPrio := float64(0)
		for _, mts := range SimilarArgMap {
			sumPrio += mts.prioSum
		}

		goal := sumPrio * rand.Float64()
		var syscall string
		sumPrio = float64(0)
		for sys, mts := range SimilarArgMap {
			sumPrio += mts.prioSum
			if sumPrio > goal {
				syscall = sys
				break
			}
		}

		fmt.Printf("Splicing syscall %s\n", syscall)

		targetMt := SimilarArgMap[syscall]

		if len(targetMt.args) == 0 {
			fmt.Printf("no similar args")
			return
		}

		for {
			arg, _, chosenIdx := targetMt.chooseType(r)
			targetArg := targetMt.similarArgs[chosenIdx].arg

			if _, ok := arg.(*prog.UnionArg); ok {
				fmt.Printf("Replacing UnionArg\n")
				fmt.Printf("Replacing %s\n", arg.Type().String())
				fmt.Printf("Before Mutation:\n%s\n", p.Serialize())
				replaceArg(arg, targetArg)
				fmt.Printf("After Mutation:\n%s\n", p.Serialize())
			} else if argGroup, ok := arg.(*prog.GroupArg); ok {
				for idx, inner := range argGroup.Inner {
					// 3 outof 10 to mutate the inner
					switch inner.Type().(type) {
					case *prog.UnionType, *prog.IntType, *prog.PtrType,
						*prog.FlagsType, *prog.LenType,
						*prog.VmaType, *prog.BufferType, *prog.ArrayType:

						targetArgGroup := targetArg.(*prog.GroupArg)
						if r.Intn(10) < 3 {
							fmt.Printf("Replacing %s(%T)\n", arg.Type().String(), inner.Type())
							fmt.Printf("Before Mutation:\n%s\n", p.Serialize())
							replaceArg(argGroup.Inner[idx], targetArgGroup.Inner[idx])
							fmt.Printf("After Mutation:\n%s\n", p.Serialize())
						}
					}
				}
			} else {
				panic("Unknown arg")
			}

			if r.Intn(5) < 3 {
				break
			}
		}

		fmt.Printf("\nBefore mutation:\n%s\n", pOriginal.Serialize())
		fmt.Printf("This is poc:\n%s\n", poc.Serialize())
		fmt.Printf("after mutation:\n%s\n", p.Serialize())

	}
}

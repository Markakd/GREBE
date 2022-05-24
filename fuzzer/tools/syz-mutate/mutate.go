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
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS     = flag.String("os", runtime.GOOS, "target os")
	flagArch   = flag.String("arch", runtime.GOARCH, "target arch")
	flagSeed   = flag.Int("seed", -1, "prng seed")
	flagLen    = flag.Int("len", prog.RecommendedCalls, "number of calls in programs")
	flagEnable = flag.String("enable", "", "comma-separated list of enabled syscalls")
	flagCorpus = flag.String("corpus", "", "name of the corpus file")
)

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
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
	seed := time.Now().UnixNano()
	if *flagSeed != -1 {
		seed = int64(*flagSeed)
	}
	corpus, err := db.ReadCorpus(*flagCorpus, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v", err)
		os.Exit(1)
	}
	rs := rand.NewSource(seed)
	ct := target.BuildChoiceTable(corpus, syscalls)
	var p *prog.Prog
	if flag.NArg() == 0 {
		p = target.Generate(rs, *flagLen, ct)
	} else {
		data, err := ioutil.ReadFile(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
			os.Exit(1)
		}
		p, err = target.Deserialize(data, prog.NonStrict)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
			os.Exit(1)
		}

		for _, c := range p.Calls {
			fmt.Printf("in syscall %s:\n", c.Meta.Name)
			prog.ForeachArg(c, func(arg prog.Arg, ctx *prog.ArgCtx) {
				fmt.Printf("%s : %s\n", arg.Type().String(), arg.Type().Name())
				fmt.Printf("Temple name: %s\n", arg.Type().TemplateName())
				fmt.Printf("Type: %T\n", arg)
				fmt.Printf("Type2: %T\n", arg.Type())
				switch a := arg.Type().(type) {
				case *prog.StructType:
					for _, f := range a.Fields {
						fmt.Printf("In structure: type: %T, name: %s, string: %s\n", f.Type, f.Type.Name(), f.Type.String())
						switch a := f.Type.(type) {
						case *prog.BufferType:
							switch a.Kind {
							case prog.BufferString:
								fmt.Printf("Value: %v\n", a.Values)

								// case prog.FlagsType:
								// 	fmt.Printf("Value: %v\n", a.Values)
							}
						}
					}

				case *prog.BufferType:
					fmt.Printf("For each: Value: %v\n", a.Values)

				case *prog.FlagsType:
				case *prog.IntType:
					fmt.Printf("FlagsType value: %v\n", arg.(*prog.ConstArg).Val)
				}

				fmt.Printf("\n")
			})
		}

		// p_raw := p.Clone()
		// fmt.Printf("Before mutating:\n%s\n", p.Serialize())
		// p.MutatePoc(rs, *flagLen, ct, corpus)
		// fmt.Printf("After mutating poc:\n%s\n", p.Serialize())
		// p_raw.Mutate(rs, *flagLen, ct, corpus)
		// fmt.Printf("original mutation:\n%s\n", p_raw.Serialize())

	}
	// fmt.Printf("%s\n", p.Serialize())
}

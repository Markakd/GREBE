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

type Arginfo struct {
	TemplateName string
	Value        prog.Arg
}

// func replaceResultArg(arg, arg1 *prog.ResultArg) {
// 	// Remove link from `a.Res` to `arg`.
// 	if arg.Res != nil {
// 		delete(arg.Res.uses, arg)
// 	}
// 	// Copy all fields from `arg1` to `arg` except for the list of args that use `arg`.
// 	uses := arg.uses
// 	*arg = *arg1
// 	arg.uses = uses
// 	// Make the link in `arg.Res` (which is now `Res` of `arg1`) to point to `arg` instead of `arg1`.
// 	if arg.Res != nil {
// 		resUses := arg.Res.uses
// 		delete(resUses, arg1)
// 		resUses[arg] = true
// 	}
// }

func replaceArg(arg, arg1 prog.Arg) {
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

func parseArg(p *prog.Prog) map[string][]prog.Arg {

	argMap := make(map[string][]prog.Arg)
	for _, c := range p.Calls {
		args := make([]prog.Arg, 0)
		prog.ForeachArg(c, func(arg prog.Arg, ctx *prog.ArgCtx) {

			switch arg.Type().(type) {
			case *prog.UnionType, *prog.ConstType, *prog.IntType,
				*prog.FlagsType, *prog.LenType, *prog.CsumType,
				*prog.VmaType, *prog.BufferType, *prog.ArrayType:
				fmt.Printf("adding %s\n", arg.Type().String())
				args = append(args, arg)
			}
		})
		argMap[c.Meta.Name] = args
	}
	return argMap
}

func logArgMap(argMap map[string][]prog.Arg) {
	for syscall, args := range argMap {
		fmt.Printf("in syscall %s\n", syscall)
		for _, arg := range args {
			fmt.Printf("arg Type %s, template: %s (%T)\n", arg.Type().String(), arg.Type().TemplateName(), arg)
		}
	}
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

	data, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}

	poc, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}

	argMaps := parseArg(poc)
	logArgMap(argMaps)

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
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Original input: %s\n", p.Serialize())

		for _, c := range p.Calls {

			args := argMaps[c.Meta.Name]

			if len(args) == 0 {
				fmt.Printf("skip %s\n", c.Meta.Name)
				continue
			}

			prog.ForeachArg(c, func(arg prog.Arg, ctx *prog.ArgCtx) {
				switch arg.(type) {
				// case *prog.UnionArg, *prog.GroupArg, *prog.StructArg:
				default:
					for _, pocArg := range args {
						if pocArg.Type().String() == arg.Type().String() &&
							pocArg.Type().TemplateName() == arg.Type().TemplateName() {
							fmt.Printf("Found %s != %s\n", pocArg.Type().String(), arg.Type().String())

							if r.Intn(8) > 1 {
								continue
							}
							replaceArg(arg, pocArg)
							fmt.Printf("after mutation: %s\n", p.Serialize())
							break
						} else {
							fmt.Printf("Skip %s != %s\n", pocArg.Type().String(), arg.Type().String())
						}
					}
				}

				// case *prog.PointerArg, *prog.UnionArg:
				// 	fmt.Printf("%s : %s\n", arg.Type().String(), arg.Type().Name())
				// 	fmt.Printf("Temple name: %s\n", arg.Type().TemplateName())
				// 	fmt.Printf("ARG: %T\n", arg)
				// 	fmt.Printf("Type2: %T\n\n", arg.Type())
				// case *prog.GroupArg:
				// 	fmt.Printf("%s : %s\n", arg.Type().String(), arg.Type().Name())
				// 	fmt.Printf("Temple name: %s\n", arg.Type().TemplateName())
				// 	fmt.Printf("ARG: %T\n", arg)
				// 	fmt.Printf("Type2: %T\n\n", arg.Type())

				// 	if typ, ok := a.Type().(*prog.StructType); ok {
				// 		fmt.Printf("Found struct: %s\n", typ.Name())
				// 		for i, fff := range typ.Fields {
				// 			fmt.Printf("Field %d: %s (%s, %T)\n", i, fff.Name, fff.Type.TemplateName(), fff.Type)
				// 		}
				// 		fmt.Printf("\n")
				// 	}
				// }

				// 1. arg.Type().String() are the same and arg.Type().TemplateName() are the same

				// fmt.Printf("%s : %s\n", arg.Type().String(), arg.Type().Name())
				// fmt.Printf("Temple name: %s\n", arg.Type().TemplateName())
				// fmt.Printf("ARG: %T\n", arg)
				// fmt.Printf("Type2: %T\n", arg.Type())
				// switch a := arg.Type().(type) {
				// case *prog.StructType:
				// 	for _, f := range a.Fields {
				// 		fmt.Printf("In structure: type: %T, name: %s, string: %s\n", f.Type, f.Type.Name(), f.Type.String())
				// 		switch a := f.Type.(type) {
				// 		case *prog.BufferType:
				// 			switch a.Kind {
				// 			case prog.BufferString:
				// 				fmt.Printf("Value: %v\n", a.Values)

				// 				// case prog.FlagsType:
				// 				// 	fmt.Printf("Value: %v\n", a.Values)
				// 			}
				// 		}
				// 	}

				// case *prog.BufferType:
				// 	fmt.Printf("For each: Value: %v\n", a.Values)

				// case *prog.FlagsType:
				// case *prog.IntType:
				// 	fmt.Printf("FlagsType value: %v\n", arg.(*prog.ConstArg).Val)
				// }

				// fmt.Printf("\n")
			})
		}

		fmt.Printf("after mutation: %s\n", p.Serialize())

	}
}

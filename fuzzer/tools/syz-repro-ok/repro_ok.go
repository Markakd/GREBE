// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "manager configuration file (manager.cfg)")
	flagCount  = flag.Int("count", 0, "number of VMs to use (overrides config count param)")
	flagDebug  = flag.Bool("debug", false, "print debug output")
	flagRepro  = flag.String("repro", "", "reproducer file")
)

func doRepro(cfg *mgrconfig.Config, logFile string) bool {
	data, err := ioutil.ReadFile(logFile)
	if err != nil {
		log.Fatalf("failed to open log file %v: %v", logFile, err)
	}
	if _, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch); err != nil {
		log.Fatalf("%v", err)
	}
	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("%v", err)
	}
	vmCount := vmPool.Count()
	if *flagCount > 0 && *flagCount < vmCount {
		vmCount = *flagCount
	}
	if vmCount > 4 {
		vmCount = 4
	}
	vmIndexes := make([]int, vmCount)
	for i := range vmIndexes {
		vmIndexes[i] = i
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}
	osutil.HandleInterrupts(vm.Shutdown)

	res, stats, err := repro.Run(data, cfg, nil, reporter, vmPool, vmIndexes)
	if err != nil {
		log.Logf(0, "reproduction failed: %v", err)
		return false
	}
	if stats != nil {
		fmt.Printf("Extracting prog: %v\n", stats.ExtractProgTime)
		fmt.Printf("Minimizing prog: %v\n", stats.MinimizeProgTime)
		fmt.Printf("Simplifying prog options: %v\n", stats.SimplifyProgTime)
		fmt.Printf("Extracting C: %v\n", stats.ExtractCTime)
		fmt.Printf("Simplifying C: %v\n", stats.SimplifyCTime)
	}
	if res == nil {
		return false
	}

	fmt.Printf("opts: %+v crepro: %v\n\n", res.Opts, res.CRepro)
	fmt.Printf("%s\n", res.Prog.Serialize())
	if res.CRepro {
		src, err := csource.Write(res.Prog, res.Opts)
		if err != nil {
			log.Fatalf("failed to generate C repro: %v", err)
			return false
		}
		if formatted, err := csource.Format(src); err == nil {
			src = formatted
		}
		fmt.Printf("%s\n", src)
		return true
	}

	return false
}

func main() {
	os.Args = append(append([]string{}, os.Args[0], "-vv=10"), os.Args[1:]...)
	flag.Parse()
	if *flagConfig == "" {
		log.Fatalf("usage: syz-repro -config=manager.cfg")
	}
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v: %v", *flagConfig, err)
	}

	if *flagRepro != "" {
		fmt.Printf("reproducing %s...", *flagRepro)
		res := doRepro(cfg, *flagRepro)
		if res == true {
			fmt.Printf("%s is reproduciable", *flagRepro)
		} else {
			fmt.Printf("%s is not reproduciable", *flagRepro)
		}
		return
	}

	workDir := filepath.Dir(*flagConfig)
	crashDir := workDir + "/crashes"

	log.Logf(0, "workdir : %v\n crash dir: %v\n", workDir, crashDir)

	unreproFile, e := os.OpenFile(workDir+"/unreproducible.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if e != nil {
		panic(err)
	}
	defer unreproFile.Close()

	files, err := ioutil.ReadDir(crashDir)
	if err != nil {
		log.Logf(0, "Fail to read crash dir %v", crashDir)
		log.Fatal(err)
	}

	for _, file := range files {
		crash := crashDir + "/" + file.Name()
		logFile := crash + "/repro.prog"
		descFile := crash + "/description"
		dat, e := ioutil.ReadFile(descFile)
		if e != nil {
			log.Logf(0, "Didn't find description for %v", crash)
			panic(e)
		}
		desc := string(dat)
		if _, err := os.Stat(crash + "/repro.prog"); os.IsNotExist(err) {
			log.Logf(0, "didn't find repro, using log0")
			logFile = crash + "/log0"
		}
		if doRepro(cfg, logFile) == false {
			if _, e = unreproFile.WriteString(desc); e != nil {
				panic(err)
			}
			log.Logf(0, "Fail to reproduce %v", desc)
		}
	}

}

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pprof

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"testing"
	"unsafe"
)

var memSink interface{}

func allocateTransient1M() {
	for i := 0; i < 1024; i++ {
		memSink = &struct{ x [1024]byte }{}
	}
}

//go:noinline
func allocateTransient2M() {
	memSink = make([]byte, 2<<20)
}

type Obj32 struct {
	link *Obj32
	pad  [32 - unsafe.Sizeof(uintptr(0))]byte
}

var persistentMemSink *Obj32

func allocatePersistent1K() {
	for i := 0; i < 32; i++ {
		// Can't use slice because that will introduce implicit allocations.
		obj := &Obj32{link: persistentMemSink}
		persistentMemSink = obj
	}
}

// Allocate transient memory using reflect.Call.

func allocateReflectTransient() {
	memSink = make([]byte, 3<<20)
}

func allocateReflect() {
	rv := reflect.ValueOf(allocateReflectTransient)
	rv.Call(nil)
}

var memoryProfilerRun = 0

func TestMemoryProfiler(t *testing.T) {
	// Disable sampling, otherwise it's difficult to assert anything.
	oldRate := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	defer func() {
		runtime.MemProfileRate = oldRate
	}()

	// Allocate a meg to ensure that mcache.next_sample is updated to 1.
	for i := 0; i < 1024; i++ {
		memSink = make([]byte, 1024)
	}

	// Do the interesting allocations.
	allocateTransient1M()
	allocateTransient2M()
	allocatePersistent1K()
	allocateReflect()
	memSink = nil

	runtime.GC() // materialize stats
	var buf bytes.Buffer
	if err := Lookup("heap").WriteTo(&buf, 1); err != nil {
		t.Fatalf("failed to write heap profile: %v", err)
	}

	memoryProfilerRun++

	tests := []string{

		fmt.Sprintf(`%v: %v \[%v: %v\] @ 0x[0-9,a-f x]+
#	0x[0-9,a-f]+	pprof\.allocatePersistent1K\+0x[0-9,a-f]+	.*/mprof_test\.go:40
#	0x[0-9,a-f]+	runtime/pprof\.TestMemoryProfiler\+0x[0-9,a-f]+	.*/mprof_test\.go:74
`, 32*memoryProfilerRun, 1024*memoryProfilerRun, 32*memoryProfilerRun, 1024*memoryProfilerRun),

		fmt.Sprintf(`0: 0 \[%v: %v\] @ 0x[0-9,a-f x]+
#	0x[0-9,a-f]+	pprof\.allocateTransient1M\+0x[0-9,a-f]+	.*/mprof_test.go:21
#	0x[0-9,a-f]+	runtime/pprof\.TestMemoryProfiler\+0x[0-9,a-f]+	.*/mprof_test.go:72
`, (1<<10)*memoryProfilerRun, (1<<20)*memoryProfilerRun),

		// This should start with "0: 0" but gccgo's imprecise
		// GC means that sometimes the value is not collected.
		fmt.Sprintf(`(0|%v): (0|%v) \[%v: %v\] @ 0x[0-9,a-f x]+
#	0x[0-9,a-f]+	pprof\.allocateTransient2M\+0x[0-9,a-f]+	.*/mprof_test.go:27
#	0x[0-9,a-f]+	runtime/pprof\.TestMemoryProfiler\+0x[0-9,a-f]+	.*/mprof_test.go:73
`, memoryProfilerRun, (2<<20)*memoryProfilerRun, memoryProfilerRun, (2<<20)*memoryProfilerRun),

		// This should start with "0: 0" but gccgo's imprecise
		// GC means that sometimes the value is not collected.
		fmt.Sprintf(`(0|%v): (0|%v) \[%v: %v\] @( 0x[0-9,a-f]+)+
#	0x[0-9,a-f]+	pprof\.allocateReflectTransient\+0x[0-9,a-f]+	.*/mprof_test.go:48
`, memoryProfilerRun, (3<<20)*memoryProfilerRun, memoryProfilerRun, (3<<20)*memoryProfilerRun),
	}

	for _, test := range tests {
		if !regexp.MustCompile(test).Match(buf.Bytes()) {
			t.Fatalf("The entry did not match:\n%v\n\nProfile:\n%v\n", test, buf.String())
		}
	}
}

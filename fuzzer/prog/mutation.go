// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sort"

	"github.com/google/syzkaller/pkg/log"
)

// Maximum length of generated binary blobs inserted into the program.
const maxBlobLen = uint64(100 << 10)

// Mutate program p.
//
// p:       The program to mutate.
// rs:      Random source.
// ncalls:  The allowed maximum calls in mutated program.
// ct:      ChoiceTable for syscalls.
// corpus:  The entire corpus, including original program p.
func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable, corpus []*Prog) {
	r := newRand(p.Target, rs)
	if ncalls < len(p.Calls) {
		ncalls = len(p.Calls)
	}
	ctx := &mutator{
		p:      p,
		r:      r,
		ncalls: ncalls,
		ct:     ct,
		corpus: corpus,
	}
	for stop, ok := false, false; !stop; stop = ok && len(p.Calls) != 0 && r.oneOf(3) {
		switch {
		case r.oneOf(5):
			// Not all calls have anything squashable,
			// so this has lower priority in reality.
			ok = ctx.squashAny()
		case r.nOutOf(1, 100):
			ok = ctx.splice()
		case r.nOutOf(20, 31):
			ok = ctx.insertCall()
		case r.nOutOf(10, 11):
			ok = ctx.mutateArg()
		default:
			ok = ctx.removeCall()
		}
	}
	p.sanitizeFix()
	p.debugValidate()
	if got := len(p.Calls); got < 1 || got > ncalls {
		panic(fmt.Sprintf("bad number of calls after mutation: %v, want [1, %v]", got, ncalls))
	}
}

type mutationTypes struct {
	target      *Target
	prioSum     float64
	args        []mutationType
	similarArgs []mutationType
	argsBuffer  [16]mutationType
}

type mutationType struct {
	arg      Arg
	ctx      ArgCtx
	priority float64
	prio     float64
}

func (mt *mutationTypes) collectTypes(arg Arg, ctx *ArgCtx) {
	pValue := float64(0)
	switch typ := arg.Type().(type) {
	case *StructType:
		log.Logf(3, "Adding StructType\n")
		for _, field := range typ.Fields {
			switch field.Type.(type) {
			case *StructType:
			case *UnionType:
			case *ConstType:
			case *CsumType:
			case *PtrType:
			case *ResourceType:
			default:
				pValue += float64(1)
			}
		}
		mt.prioSum += pValue
		mt.args = append(mt.args, mutationType{arg, *ctx, mt.prioSum, pValue})

	case *UnionType:
		log.Logf(3, "Adding UnionType\n")
		mt.prioSum += float64(3)
		mt.args = append(mt.args, mutationType{arg, *ctx, mt.prioSum, pValue})
	}
}

func (mt *mutationTypes) chooseType(r *rand.Rand) (Arg, ArgCtx, int) {
	goal := mt.prioSum * r.Float64()
	chosenIdx := sort.Search(len(mt.args), func(i int) bool { return mt.args[i].priority >= goal })
	arg := mt.args[chosenIdx]
	return arg.arg, arg.ctx, chosenIdx
}

func parseArg(p *Prog) map[string]mutationTypes {
	argMap := make(map[string]mutationTypes)
	for _, c := range p.Calls {
		// fmt.Printf("syscall: %s\n", c.Meta.Name)
		mt := &mutationTypes{target: p.Target, prioSum: float64(0)}
		ForeachArg(c, mt.collectTypes)
		// for _, aa := range mt.args {
		// 	fmt.Printf("This is the arg: %s(%T): %s\n", aa.arg.Type().String(), aa.arg, aa.arg)
		// }
		if mt.prioSum == 0 {
			continue
		}
		argMap[c.Meta.Name] = *mt
	}
	return argMap
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
							log.Logf(3, "Adding: %s\n", argA.arg.Type().String())
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

// SplicePoc: given a poc, splice the seed with the poc
func (p *Prog) SplicePoc(rs rand.Source, poc *Prog) bool {
	r := newRand(p.Target, rs)
	PocArgMaps := parseArg(poc)
	SimilarArgMap := getSimilarTypes(parseArg(p), PocArgMaps)

	if len(SimilarArgMap) == 0 {
		log.Logf(3, "No similar input\n")
		return false
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
		syscall = sys
		if sumPrio > goal {
			break
		}
	}

	targetMt := SimilarArgMap[syscall]
	if len(targetMt.args) == 0 {
		log.Logf(3, "no similar arg in %s\n", syscall)
		return false
	}

	for {
		arg, _, chosenIdx := targetMt.chooseType(r.Rand)
		targetArg := targetMt.similarArgs[chosenIdx].arg

		if _, ok := arg.(*UnionArg); ok {
			log.Logf(3, "UnionArg: Replacing %s\n", arg.Type().String())
			log.Logf(3, "Before Mutation:\n%s\n", p.Serialize())
			log.Logf(3, "Replacing %s with %s\n", arg, targetArg)
			replaceArg(arg, targetArg)
			log.Logf(3, "After Mutation:\n%s\n", p.Serialize())
		} else if argGroup, ok := arg.(*GroupArg); ok {
			for idx, inner := range argGroup.Inner {
				// 3 outof 10 to mutate the inner
				switch inner.Type().(type) {
				case *UnionType, *IntType,
					*FlagsType, *BufferType, *ArrayType:

					targetArgGroup := targetArg.(*GroupArg)
					if r.Intn(10) < 3 {
						log.Logf(3, "Replacing %s(%T)\n", arg.Type().String(), inner.Type())
						log.Logf(3, "Before Mutation:\n%s\n", p.Serialize())
						log.Logf(3, "Replacing %s with %s\n", argGroup.Inner[idx], targetArgGroup.Inner[idx])
						replaceArg(argGroup.Inner[idx], targetArgGroup.Inner[idx])
						log.Logf(3, "After Mutation:\n%s\n", p.Serialize())
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
	return true
}

// MutatePoc : Given a poc that causes a crash to the kernel
// we will keep mutating on that poc to find more
// behaviors of that bug.
// insert calls, remove calls
// replace calls.
func (p *Prog) MutatePoc(rs rand.Source, ncalls int, ct *ChoiceTable, corpus []*Prog) {
	log.Logf(2, "Mutating Poc:\n%s", p.Serialize())
	r := newRand(p.Target, rs)
	if ncalls < len(p.Calls) {
		ncalls = len(p.Calls)
	}
	ctx := &mutator{
		p:      p,
		r:      r,
		ncalls: ncalls,
		ct:     ct,
		corpus: corpus,
	}

	var count int

	for ok := false; !ok; {
		switch {
		case r.nOutOf(1, 10):
			// let's reduce the probability of mutating args since mutating args
			// still lets the kernel crash in most cases. When the kernel keeps
			// crashing, the over all effeciency of fuzzing will be reduced.
			// log.Logf(2, "mutate Type!\n")
			// ok = ctx.mutateType()
			ok = ctx.mutateArg()
		case r.nOutOf(3, 10):
			log.Logf(2, "ReplaceCall!\n")
			ok = ctx.replaceCall()
		case r.nOutOf(5, 10):
			log.Logf(2, "mutate and replace\n")
			ctx.mutateArg()
			ok = ctx.replaceCall()
		case r.nOutOf(9, 10):
			// insert
			log.Logf(2, "mutate and insertCalls!\n")
			ok = ctx.mutateArg()
			ok = ctx.insertCall()
		default:
			log.Logf(2, "remove non res call!\n")
			// ok = ctx.removeNonResCall()
			ok = ctx.removeCall()
		}

		count++
		if count == 8 {
			panic("keeps failing in mutatePoc")
		}
	}

	p.sanitizeFix()
	p.debugValidate()
	if got := len(p.Calls); got < 1 || got > ncalls {
		panic(fmt.Sprintf("bad number of calls after mutationPoc: %v, want [1, %v]", got, ncalls))
	}
	// execution will log the program
	log.Logf(3, "After mutating, the poc looks like:\n%s", p.Serialize())
}

// export this function for calls coming from syz-fuzzer
func (p *Prog) RemoveCall(idx int) {
	p.removeCall(idx)
}

// Internal state required for performing mutations -- currently this matches
// the arguments passed to Mutate().
type mutator struct {
	p      *Prog        // The program to mutate.
	r      *randGen     // The randGen instance.
	ncalls int          // The allowed maximum calls in mutated program.
	ct     *ChoiceTable // ChoiceTable for syscalls.
	corpus []*Prog      // The entire corpus, including original program p.
}

// This function selects a random other program p0 out of the corpus, and
// mutates ctx.p as follows: preserve ctx.p's Calls up to a random index i
// (exclusive) concatenated with p0's calls from index i (inclusive).
func (ctx *mutator) splice() bool {
	p, r := ctx.p, ctx.r
	if len(ctx.corpus) == 0 || len(p.Calls) == 0 || len(p.Calls) >= ctx.ncalls {
		return false
	}
	p0 := ctx.corpus[r.Intn(len(ctx.corpus))]
	p0c := p0.Clone()
	idx := r.Intn(len(p.Calls))
	p.Calls = append(p.Calls[:idx], append(p0c.Calls, p.Calls[idx:]...)...)
	for i := len(p.Calls) - 1; i >= ctx.ncalls; i-- {
		p.removeCall(i)
	}
	return true
}

// Picks a random complex pointer and squashes its arguments into an ANY.
// Subsequently, if the ANY contains blobs, mutates a random blob.
func (ctx *mutator) squashAny() bool {
	p, r := ctx.p, ctx.r
	complexPtrs := p.complexPtrs()
	if len(complexPtrs) == 0 {
		return false
	}
	ptr := complexPtrs[r.Intn(len(complexPtrs))]
	if !p.Target.isAnyPtr(ptr.Type()) {
		p.Target.squashPtr(ptr)
	}
	var blobs []*DataArg
	var bases []*PointerArg
	ForeachSubArg(ptr, func(arg Arg, ctx *ArgCtx) {
		if data, ok := arg.(*DataArg); ok && arg.Dir() != DirOut {
			blobs = append(blobs, data)
			bases = append(bases, ctx.Base)
		}
	})
	if len(blobs) == 0 {
		return false
	}
	// TODO(dvyukov): we probably want special mutation for ANY.
	// E.g. merging adjacent ANYBLOBs (we don't create them,
	// but they can appear in future); or replacing ANYRES
	// with a blob (and merging it with adjacent blobs).
	idx := r.Intn(len(blobs))
	arg := blobs[idx]
	base := bases[idx]
	baseSize := base.Res.Size()
	arg.data = mutateData(r, arg.Data(), 0, maxBlobLen)
	// Update base pointer if size has increased.
	if baseSize < base.Res.Size() {
		s := analyze(ctx.ct, ctx.corpus, p, p.Calls[0])
		newArg := r.allocAddr(s, base.Type(), base.Dir(), base.Res.Size(), base.Res)
		*base = *newArg
	}
	return true
}

// Inserts a new call at a randomly chosen point (with bias towards the end of
// existing program). Does not insert a call if program already has ncalls.
func (ctx *mutator) insertCall() bool {
	log.Logf(2, "Inserting calls in the original mutation\n")
	p, r := ctx.p, ctx.r
	if len(p.Calls) >= ctx.ncalls {
		return false
	}
	idx := r.biasedRand(len(p.Calls)+1, 5)
	var c *Call
	if idx < len(p.Calls) {
		c = p.Calls[idx]
	}
	s := analyze(ctx.ct, ctx.corpus, p, c)
	calls := r.generateCall(s, p, idx)
	p.insertBefore(c, calls)
	for len(p.Calls) > ctx.ncalls {
		p.removeCall(idx)
	}
	return true
}

// insert a resource consuming call
func (ctx *mutator) insertResCall() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) >= ctx.ncalls {
		return false
	}
	callList := make([]int, 0)
	useList := make([]int, 0)
	for idx, call := range p.Calls {
		meta := call.Meta

		if meta.Name == "mmap" {
			continue
		}

		res := p.Target.getOutputResources(meta)
		if len(res) != 0 {
			callList = append(callList, idx)
		} else {
			useList = append(useList, idx)
		}
	}
	log.Logf(3, "callList: %v, useList: %v\n", callList, useList)

	use := true
	var idx int
	if len(useList) > 0 {
		idx = useList[r.Intn(len(useList))]
	} else if len(callList) > 0 {
		idx = callList[r.Intn(len(callList))]
	} else {
		return false
	}

	if r.oneOf(10) {
		log.Logf(3, "Insert resource generating\n")
		use = false
	}

	var c *Call
	if idx < len(p.Calls) {
		log.Logf(3, "idx: %d, len of p.Calls: %d\n", idx, len(p.Calls))
		c = p.Calls[idx]
	}
	s := analyze(ctx.ct, ctx.corpus, p, c)

	var calls []*Call
	if use {
		log.Logf(3, "Insert resource use call\n")
		calls = r.generateResUseCall(s, p, idx)
	} else {
		log.Logf(3, "Insert resource call\n")
		calls = r.generateResCall(s, p, idx)
	}

	for _, cc := range calls {
		log.Logf(5, "Inserting %v in insertResCall\n", cc.Meta.Name)
	}

	p.insertBefore(c, calls)

	for len(p.Calls) > ctx.ncalls {
		p.removeCall(idx)
	}
	return true
}

func debugChoiceTable(ct *ChoiceTable) {
	for i := range ct.runs {
		for j := range ct.runs[i] {
			log.Logf(3, "%v -> %v : %v\n", ct.target.Syscalls[i].Name, ct.target.Syscalls[j].Name, ct.runs[i][j])
		}
	}
}

func (ctx *mutator) replaceCall() bool {
	if ctx.r.nOutOf(1, 2) {
		return ctx.replaceResCall()
	} else {
		return ctx.replaceUseCall()
	}
}

func (ctx *mutator) doReplace() bool {
	log.Logf(3, "ReplaceCall!\n")
	p, r := ctx.p, ctx.r
	ncalls := len(p.Calls)
	idx := r.Intn(ncalls)
	call := p.Calls[idx]
	isUse := false

	for i := 0; i < ncalls; i++ {
		meta := call.Meta
		// check if it's resource use or resource generating
		res := p.Target.getOutputResources(meta)
		if len(res) == 0 {
			isUse = true
		}
		if meta.Name != "mmap" {
			break
		}
		idx = r.Intn(ncalls)
		call = p.Calls[idx]
	}

	biasCall := call.Meta.ID
	s := analyze(ctx.ct, ctx.corpus, p, call)

	for {
		i := s.ct.choose(r.Rand, biasCall)
		meta := r.target.Syscalls[i]

		if isUse {
			if len(p.Target.getOutputResources(meta)) > 0 {
				continue
			}
		} else {
			if len(p.Target.getOutputResources(meta)) == 0 {
				continue
			}
		}
		calls := r.generateParticularCall(s, meta)
		insertPoint := call
		p.insertAfter(insertPoint, calls)

		debug := true
		if debug {
			for _, cc := range calls {
				log.Logf(3, "Inserting %v in do replace\n", cc.Meta.Name)
			}
		}

		// 2/3 probability to return
		if r.nOutOf(2, 3) {
			for len(p.Calls) > ctx.ncalls {
				p.removeCall(idx)
			}
			if r.nOutOf(7, 8) {
				log.Logf(3, "Removing %v\n", p.Calls[idx].Meta.Name)
				p.removeCallc(p.Calls[idx])
			}

			return true
		}
	}
}

func (ctx *mutator) replaceResCall() bool {
	log.Logf(2, "ReplaceResCall!\n")
	p, r := ctx.p, ctx.r
	callList := make([]int, 0)
	useList := make([]int, 0)

	for idx, call := range p.Calls {
		meta := call.Meta

		if meta.Name == "mmap" {
			continue
		}

		res := p.Target.getOutputResources(meta)
		if len(res) != 0 {
			callList = append(callList, idx)
		} else {
			useList = append(useList, idx)
		}
	}

	if len(callList) == 0 {
		// return false
		// resource generation call maybe removed by mutatePoc accidentally
		// let's use useList instead
		callList = useList

		if len(callList) == 0 {
			return false
		}
	}

	idx := callList[r.rand(len(callList))]
	c := p.Calls[idx]
	biasCall := c.Meta.ID
	s := analyze(ctx.ct, ctx.corpus, p, c)

	for {
		i := s.ct.choose(r.Rand, biasCall)
		meta := r.target.Syscalls[i]
		if len(p.Target.getOutputResources(meta)) > 0 {
			calls := r.generateParticularCall(s, meta)

			p.insertBefore(c, calls)

			debug := true
			if debug {
				for _, cc := range calls {
					log.Logf(5, "Inserting %v in replaceResCall\n", cc.Meta.Name)
				}
			}

			// 2/3 probability to return
			if r.nOutOf(2, 3) {
				for len(p.Calls) > ctx.ncalls {
					p.removeCall(idx)
				}
				p.removeCallc(c)

				return true
			}
		}
	}
}

// replace a consuming call with another consuming call
func (ctx *mutator) replaceUseCall() bool {
	log.Logf(3, "ReplaceUseCall!\n")
	p, r := ctx.p, ctx.r
	callList := make([]int, 0)
	useList := make([]int, 0)
	for idx, call := range p.Calls {
		meta := call.Meta

		if meta.Name == "mmap" {
			continue
		}

		res := p.Target.getOutputResources(meta)
		if len(res) != 0 {
			callList = append(callList, idx)
		} else {
			useList = append(useList, idx)
		}
	}

	if len(callList) == 0 {
		// return false
		// resource generation call maybe removed by mutatePoc accidentally
		// let's use useList instead
		callList = useList
	}

	// get a biascall
	idx := callList[r.rand(len(callList))]
	resCall := p.Calls[idx]

	// this call is going to be removed
	c := resCall
	if len(useList) > 0 {
		idx = useList[r.rand(len(useList))]
		c = p.Calls[idx]
	}

	// generate a use call consuming the res from the callList
	biasCall := resCall.Meta.ID
	s := analyze(ctx.ct, ctx.corpus, p, c)
	for {
		i := s.ct.choose(r.Rand, biasCall)
		meta := r.target.Syscalls[i]
		if len(p.Target.getOutputResources(meta)) == 0 {
			calls := r.generateParticularCall(s, meta)

			p.insertBefore(c, calls)

			debug := true
			if debug {
				for _, cc := range calls {
					log.Logf(5, "Inserting %v in replaceUseCall\n", cc.Meta.Name)
				}
			}

			// 2/3 probability to return
			if r.nOutOf(2, 3) {
				for len(p.Calls) > ctx.ncalls {
					p.removeCall(idx)
				}
				p.removeCallc(c)
				return true
			}
		}
	}
}

// Removes a random call from program.
func (ctx *mutator) removeCall() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) == 1 {
		return false
	}
	idx := r.Intn(len(p.Calls))
	p.removeCall(idx)
	return true
}

func (ctx *mutator) removeNonResCall() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) == 0 {
		return false
	}

	callList := make([]int, 0)
	useList := make([]int, 0)
	for idx, call := range p.Calls {
		meta := call.Meta
		res := p.Target.getOutputResources(meta)
		if len(res) != 0 {
			callList = append(callList, idx)
		} else {
			useList = append(useList, idx)
		}
	}

	var idx int
	if len(callList) == len(p.Calls) {
		idx = r.Intn(len(p.Calls))
	} else {
		idx = useList[r.Intn(len(useList))]
	}
	p.removeCall(idx)
	return true
}

// Mutate an argument of a random call.
func (ctx *mutator) mutateArg() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) == 0 {
		return false
	}

	idx := chooseCall(p, r)
	if idx < 0 {
		return false
	}
	c := p.Calls[idx]
	updateSizes := true
	for stop, ok := false, false; !stop; stop = ok && r.oneOf(3) {
		ok = true
		ma := &mutationArgs{target: p.Target}
		ForeachArg(c, ma.collectArg)
		if len(ma.args) == 0 {
			return false
		}
		s := analyze(ctx.ct, ctx.corpus, p, c)
		arg, argCtx := ma.chooseArg(r.Rand)
		calls, ok1 := p.Target.mutateArg(r, s, arg, argCtx, &updateSizes)
		if !ok1 {
			ok = false
			continue
		}
		p.insertBefore(c, calls)
		idx += len(calls)
		for len(p.Calls) > ctx.ncalls {
			idx--
			p.removeCall(idx)
		}
		if idx < 0 || idx >= len(p.Calls) || p.Calls[idx] != c {
			panic(fmt.Sprintf("wrong call index: idx=%v calls=%v p.Calls=%v ncalls=%v",
				idx, len(calls), len(p.Calls), ctx.ncalls))
		}
		if updateSizes {
			p.Target.assignSizesCall(c)
		}
	}
	return true
}

// mutate IntType, FlagsType, LenType, BufferType, ArrayType, ConstType
func (ctx *mutator) mutateType() bool {
	p, r := ctx.p, ctx.r
	if len(p.Calls) == 0 {
		return false
	}

	idx := chooseCallBiased(p, r)
	if idx < 0 {
		log.Logf(3, "no call has candidate arg!\n")
		return false
	}
	c := p.Calls[idx]
	updateSizes := true
	for stop, ok := false, false; !stop; stop = ok {
		ok = true
		ma := &mutationArgs{target: p.Target}
		ForeachArg(c, ma.collectArgType)
		if len(ma.args) == 0 {
			log.Logf(3, "length of args == 0\n")
			return false
		}
		s := analyze(ctx.ct, ctx.corpus, p, c)
		arg, argCtx := ma.chooseArg(r.Rand)
		log.Logf(2, "Mutating %v in %v\n", arg.Type().TemplateName(), c.Meta.Name)
		calls, ok1 := p.Target.mutateArg(r, s, arg, argCtx, &updateSizes)
		if !ok1 {
			ok = false
			continue
		}
		p.insertBefore(c, calls)
		idx += len(calls)
		for len(p.Calls) > ctx.ncalls {
			idx--
			p.removeCall(idx)
		}
		if idx < 0 || idx >= len(p.Calls) || p.Calls[idx] != c {
			panic(fmt.Sprintf("wrong call index: idx=%v calls=%v p.Calls=%v ncalls=%v",
				idx, len(calls), len(p.Calls), ctx.ncalls))
		}
		if updateSizes {
			p.Target.assignSizesCall(c)
		}
	}
	return true
}

// Select a call based on the complexity of the arguments.
func chooseCall(p *Prog, r *randGen) int {
	var prioSum float64
	var callPriorities []float64
	for _, c := range p.Calls {
		var totalPrio float64
		ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
			prio, stopRecursion := arg.Type().getMutationPrio(p.Target, arg, false)
			totalPrio += prio
			ctx.Stop = stopRecursion
		})
		prioSum += totalPrio
		callPriorities = append(callPriorities, prioSum)
	}
	if prioSum == 0 {
		return -1 // All calls are without arguments.
	}
	return sort.SearchFloat64s(callPriorities, prioSum*r.Float64())
}

// collect the complexity of IntType, FlagsType,
// LenType, BufferType, ArrayType
func collectTypePrio(arg Arg, target *Target) (float64, []float64) {
	var prio float64
	var prioArray []float64
	// seen := make(map[Type]bool)
	var rec func(Type, Dir)
	rec = func(ptr Type, dir Dir) {
		switch a := (ptr).(type) {
		case *PtrType:
			// we don't want to mutate ptr
			// rec(a.Elem, a.ElemDir)
		case *ArrayType:
			t := ptr.(*ArrayType)
			if t.RangeBegin != t.RangeEnd {
				// don't mutate fixed range array
				prio += 0.8 * maxPriority
				prioArray = append(prioArray, prio)
			}
			// rec(a.Elem, dir)
		case *StructType, *UnionType:
			// if seen[a] {
			// 	break // prune recursion via pointers to structs/unions
			// }
			// seen[a] = true
			// for i := range a.Fields {
			// 	rec(a.Fields[i].Type, dir)
			// }
			// TODO
			if target.SpecialTypes[a.Name()] != nil {
				log.Logf(3, "Got StructType %v\n", a.Name())
				prio += 2 * maxPriority
				prioArray = append(prioArray, prio)
			}
		// case *UnionType:
		// if seen[a] {
		// 	break // prune recursion via pointers to structs/unions
		// }
		// seen[a] = true
		// for i := range a.Fields {
		// 	rec(a.Fields[i].Type, dir)
		// }
		case *BufferType:
			log.Logf(3, "Got buffer value: %v\n", a.Values)
			if len(a.Values) > 0 && a.Kind == BufferString {
				prio += maxPriority * 2
				prioArray = append(prioArray, prio)
			}
		case *IntType, *LenType:
			prio += 0.8 * maxPriority
			prioArray = append(prioArray, prio)
		case *FlagsType:
			prio += 1.5 * maxPriority
			prioArray = append(prioArray, prio)
		case *ResourceType, *VmaType,
			*ConstType, *ProcType, *CsumType:
		case Ref:
			// This is only needed for pkg/compiler.
		// case Type:
		// 	rec()
		default:
			fmt.Printf("Type %T\n", ptr)
			panic("unknown type")
		}
	}
	rec(arg.Type(), arg.Dir())
	return prio, prioArray
}

// chooseCallBiased
// Select a call based on the complexity of Type.
// mutate IntType, FlagsType, LenType, BufferType, ArrayType, ConstType
// huristics: skip mmap
func chooseCallBiased(p *Prog, r *randGen) int {
	var prioSum float64
	var callPriorities []float64
	for _, c := range p.Calls {
		var totalPrio float64
		// ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
		// 	switch a := arg.(type) {
		// 	case *ConstArg:
		// 		switch a.Type().(type) {
		// 		case *FlagsType, *IntType, *LenType, *ArrayType, *ConstType:
		// 			fmt.Printf("Got flagsType\n")
		// 			prio, stopRecursion := arg.Type().getMutationPrio(p.Target, arg, false)
		// 			totalPrio += prio
		// 			ctx.Stop = stopRecursion
		// 		}
		// 	default:
		// 	}
		// })
		ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
			prio, _ := collectTypePrio(arg, r.target)
			totalPrio += prio
			// _, stopRecursion := arg.Type().getMutationPrio(p.Target, arg, false)
			// ctx.Stop = stopRecursion
			log.Logf(2, "Got prio %v for %v in %v\n", prio, arg.Type().String(), c.Meta.Name)
		})
		// foreachTypeImpl(c.Meta, false, func(typ Type, ctx TypeCtx) {
		// 	switch a := typ.(type) {
		// 	case *FlagsType:
		// 		totalPrio += maxPriority
		// 	case *IntType, *LenType, *ArrayType:
		// 		totalPrio += 0.8 * maxPriority
		// 	case *BufferType:
		// 		if len(a.Values) > 1 && a.Kind == BufferString {
		// 			totalPrio += maxPriority * 2
		// 		}
		// 	}
		// })
		// for i := range c.Args {
		// 	arg := c.Args[i]
		// 	prio, _ := collectTypePrio(arg)
		// 	totalPrio += prio
		// 	fmt.Printf("Got prio %v for %v in %v\n", prio, arg.Type().String(), c.Meta.Name)
		// }
		if c.Meta.Name == "mmap" {
			totalPrio = 0.0
			log.Logf(2, "set 0 prio for mmap\n")
		}
		prioSum += totalPrio
		callPriorities = append(callPriorities, prioSum)
	}
	if prioSum == 0 {
		return -1 // All calls are without arguments.
	}
	return sort.SearchFloat64s(callPriorities, prioSum*r.Float64())
}

// Select a call based on the complexity of the flag arguments.
// func chooseFlagCall(p *Prog, r *randGen) int {
// 	var prioSum float64
// 	var callPriorities []float64
// 	for _, c := range p.Calls {
// 		var totalPrio float64
// 		ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
// 			prio, stopRecursion := arg.Type().getMutationPrio(p.Target, arg, false)
// 			totalPrio += prio
// 			ctx.Stop = stopRecursion
// 		})
// 		prioSum += totalPrio
// 		callPriorities = append(callPriorities, prioSum)
// 	}
// 	if prioSum == 0 {
// 		return -1 // All calls are without arguments.
// 	}
// 	return sort.SearchFloat64s(callPriorities, prioSum*r.Float64())
// }

// func (target *Target) mutateType(r *randGen, s *state, arg Arg, ctx ArgCtx, updateSizes *bool) ([]*Call, bool) {
// 	var baseSize uint64
// 	if ctx.Base != nil {
// 		baseSize = ctx.Base.Res.Size()
// 	}

// 	prioSum, prio := collectTypePrio(arg)
// 	idx := sort.SearchFloat64s(prio, prioSum*r.Float64())
// 	// FIXME: use idx to calc the type
// 	tPrio := prio[idx]

// 	var tmpPrio float64
// 	seen := make(map[Type]bool)
// 	var rec func(*Type, Dir)
// 	var tTyp Type
// 	rec = func(ptr *Type, dir Dir) {
// 		switch a := (*ptr).(type) {
// 		case *PtrType:
// 			// we don't want to mutate ptr
// 			rec(&a.Elem, a.ElemDir)
// 		case *ArrayType:
// 			tmpPrio += 0.8 * maxPriority
// 			if tmpPrio >= tPrio {
// 				tTyp = a
// 				break
// 			}
// 			rec(&a.Elem, dir)
// 		case *StructType:
// 			if seen[a] {
// 				break // prune recursion via pointers to structs/unions
// 			}
// 			seen[a] = true
// 			for i := range a.Fields {
// 				rec(&a.Fields[i].Type, dir)
// 			}
// 		case *UnionType:
// 			if seen[a] {
// 				break // prune recursion via pointers to structs/unions
// 			}
// 			seen[a] = true
// 			for i := range a.Fields {
// 				rec(&a.Fields[i].Type, dir)
// 			}
// 		case *BufferType:
// 			if len(a.Values) > 1 && a.Kind == BufferString {
// 				tmpPrio += maxPriority * 2
// 				if tmpPrio >= tPrio {
// 					tTyp = a
// 					break
// 				}
// 			}
// 		case *IntType, *LenType:
// 			tmpPrio += 0.8 * maxPriority
// 			if tmpPrio >= tPrio {
// 				tTyp = a
// 				break
// 			}
// 		case *FlagsType:
// 			tmpPrio += 1.5 * maxPriority
// 			if tmpPrio >= tPrio {
// 				tTyp = a
// 				break
// 			}
// 		case *ResourceType, *VmaType,
// 			*ConstType, *ProcType, *CsumType:
// 		case Ref:
// 			// This is only needed for pkg/compiler.
// 		default:
// 			panic("unknown type")
// 		}
// 	}
// 	typ := arg.Type()
// 	rec(&typ, arg.Dir())

// 	fmt.Printf("Mutating %v %T\n", tTyp.TemplateName(), tTyp)
// 	calls, retry, preserve := tTyp.mutate(r, s, arg, ctx)
// 	if retry {
// 		return nil, false
// 	}
// 	if preserve {
// 		*updateSizes = false
// 	}
// 	// Update base pointer if size has increased.
// 	if base := ctx.Base; base != nil && baseSize < base.Res.Size() {
// 		newArg := r.allocAddr(s, base.Type(), base.Dir(), base.Res.Size(), base.Res)
// 		replaceArg(base, newArg)
// 	}
// 	return calls, true
// }

func (target *Target) mutateArg(r *randGen, s *state, arg Arg, ctx ArgCtx, updateSizes *bool) ([]*Call, bool) {
	var baseSize uint64
	if ctx.Base != nil {
		baseSize = ctx.Base.Res.Size()
	}
	calls, retry, preserve := arg.Type().mutate(r, s, arg, ctx)
	if retry {
		return nil, false
	}
	if preserve {
		*updateSizes = false
	}
	// Update base pointer if size has increased.
	if base := ctx.Base; base != nil && baseSize < base.Res.Size() {
		newArg := r.allocAddr(s, base.Type(), base.Dir(), base.Res.Size(), base.Res)
		replaceArg(base, newArg)
	}
	return calls, true
}

func regenerate(r *randGen, s *state, arg Arg) (calls []*Call, retry, preserve bool) {
	var newArg Arg
	newArg, calls = r.generateArg(s, arg.Type(), arg.Dir())
	replaceArg(arg, newArg)
	return
}

func mutateInt(r *randGen, a *ConstArg, t *IntType) uint64 {
	switch {
	case r.nOutOf(1, 3):
		return a.Val + (uint64(r.Intn(4)) + 1)
	case r.nOutOf(1, 2):
		return a.Val - (uint64(r.Intn(4)) + 1)
	default:
		return a.Val ^ (1 << uint64(r.Intn(int(t.TypeBitSize()))))
	}
}

func mutateAlignedInt(r *randGen, a *ConstArg, t *IntType) uint64 {
	rangeEnd := t.RangeEnd
	if t.RangeBegin == 0 && int64(rangeEnd) == -1 {
		// Special [0:-1] range for all possible values.
		rangeEnd = uint64(1<<t.TypeBitSize() - 1)
	}
	index := (a.Val - t.RangeBegin) / t.Align
	misalignment := (a.Val - t.RangeBegin) % t.Align
	switch {
	case r.nOutOf(1, 3):
		index += uint64(r.Intn(4)) + 1
	case r.nOutOf(1, 2):
		index -= uint64(r.Intn(4)) + 1
	default:
		index ^= 1 << uint64(r.Intn(int(t.TypeBitSize())))
	}
	lastIndex := (rangeEnd - t.RangeBegin) / t.Align
	index %= lastIndex + 1
	return t.RangeBegin + index*t.Align + misalignment
}

func (t *IntType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	if r.bin() {
		return regenerate(r, s, arg)
	}
	a := arg.(*ConstArg)
	if t.Align == 0 {
		a.Val = mutateInt(r, a, t)
	} else {
		a.Val = mutateAlignedInt(r, a, t)
	}
	a.Val = truncateToBitSize(a.Val, t.TypeBitSize())
	return
}

func (t *FlagsType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	a := arg.(*ConstArg)
	for oldVal := a.Val; oldVal == a.Val; {
		a.Val = r.flags(t.Vals, t.BitMask, a.Val)
	}
	return
}

func (t *LenType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	if !r.mutateSize(arg.(*ConstArg), *ctx.Parent, ctx.Fields) {
		retry = true
		return
	}
	preserve = true
	return
}

func (t *ResourceType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *VmaType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *ProcType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	return regenerate(r, s, arg)
}

func (t *BufferType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	minLen, maxLen := uint64(0), maxBlobLen
	if t.Kind == BufferBlobRange {
		minLen, maxLen = t.RangeBegin, t.RangeEnd
	}
	a := arg.(*DataArg)
	if a.Dir() == DirOut {
		mutateBufferSize(r, a, minLen, maxLen)
		return
	}
	switch t.Kind {
	case BufferBlobRand, BufferBlobRange:
		data := append([]byte{}, a.Data()...)
		a.data = mutateData(r, data, minLen, maxLen)
	case BufferString:
		if len(t.Values) != 0 {
			a.data = r.randString(s, t)
		} else {
			if t.TypeSize != 0 {
				minLen, maxLen = t.TypeSize, t.TypeSize
			}
			data := append([]byte{}, a.Data()...)
			a.data = mutateData(r, data, minLen, maxLen)
		}
	case BufferFilename:
		a.data = []byte(r.filename(s, t))
	case BufferText:
		data := append([]byte{}, a.Data()...)
		a.data = r.mutateText(t.Text, data)
	default:
		panic("unknown buffer kind")
	}
	return
}

func mutateBufferSize(r *randGen, arg *DataArg, minLen, maxLen uint64) {
	for oldSize := arg.Size(); oldSize == arg.Size(); {
		arg.size += uint64(r.Intn(33)) - 16
		if arg.size < minLen {
			arg.size = minLen
		}
		if arg.size > maxLen {
			arg.size = maxLen
		}
	}
}

func (t *ArrayType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	// TODO: swap elements of the array
	a := arg.(*GroupArg)
	count := uint64(0)
	switch t.Kind {
	case ArrayRandLen:
		if r.bin() {
			for count = uint64(len(a.Inner)); r.bin(); {
				count++
			}
		} else {
			for count == uint64(len(a.Inner)) {
				count = r.randArrayLen()
			}
		}
	case ArrayRangeLen:
		if t.RangeBegin == t.RangeEnd {
			panic("trying to mutate fixed length array")
		}
		for count == uint64(len(a.Inner)) {
			count = r.randRange(t.RangeBegin, t.RangeEnd)
		}
	}
	if count > uint64(len(a.Inner)) {
		for count > uint64(len(a.Inner)) {
			newArg, newCalls := r.generateArg(s, t.Elem, a.Dir())
			a.Inner = append(a.Inner, newArg)
			calls = append(calls, newCalls...)
			for _, c := range newCalls {
				s.analyze(c)
			}
		}
	} else if count < uint64(len(a.Inner)) {
		for _, arg := range a.Inner[count:] {
			removeArg(arg)
		}
		a.Inner = a.Inner[:count]
	}
	return
}

func (t *PtrType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	a := arg.(*PointerArg)
	if r.oneOf(1000) {
		removeArg(a.Res)
		index := r.rand(len(r.target.SpecialPointers))
		newArg := MakeSpecialPointerArg(t, a.Dir(), index)
		replaceArg(arg, newArg)
		return
	}
	newArg := r.allocAddr(s, t, a.Dir(), a.Res.Size(), a.Res)
	replaceArg(arg, newArg)
	return
}

func (t *StructType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	// log.Logf(3, "Mutating stuctType: %s\n", t.Name())
	// log.Logf(3, "gen func: %v\n", r.target.SpecialTypes)
	gen := r.target.SpecialTypes[t.Name()]
	if gen == nil {
		panic("bad arg returned by mutationArgs: StructType")
	}
	var newArg Arg
	newArg, calls = gen(&Gen{r, s}, t, arg.Dir(), arg)
	a := arg.(*GroupArg)
	for i, f := range newArg.(*GroupArg).Inner {
		replaceArg(a.Inner[i], f)
	}
	return
}

func (t *UnionType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	if gen := r.target.SpecialTypes[t.Name()]; gen != nil {
		var newArg Arg
		newArg, calls = gen(&Gen{r, s}, t, arg.Dir(), arg)
		replaceArg(arg, newArg)
		return
	}
	a := arg.(*UnionArg)
	index := r.Intn(len(t.Fields) - 1)
	if index >= a.Index {
		index++
	}
	optType := t.Fields[index].Type
	removeArg(a.Option)
	var newOpt Arg
	newOpt, calls = r.generateArg(s, optType, a.Dir())
	replaceArg(arg, MakeUnionArg(t, a.Dir(), newOpt, index))
	return
}

func (t *CsumType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	panic("CsumType can't be mutated")
}

func (t *ConstType) mutate(r *randGen, s *state, arg Arg, ctx ArgCtx) (calls []*Call, retry, preserve bool) {
	panic("ConstType can't be mutated")
}

type mutationArgs struct {
	target        *Target
	ignoreSpecial bool
	prioSum       float64
	args          []mutationArg
	argsBuffer    [16]mutationArg
}

type mutationArg struct {
	arg      Arg
	ctx      ArgCtx
	priority float64
}

const (
	maxPriority = float64(10)
	minPriority = float64(1)
	dontMutate  = float64(0)
)

func (ma *mutationArgs) collectArg(arg Arg, ctx *ArgCtx) {
	ignoreSpecial := ma.ignoreSpecial
	ma.ignoreSpecial = false

	typ := arg.Type()
	prio, stopRecursion := typ.getMutationPrio(ma.target, arg, ignoreSpecial)
	ctx.Stop = stopRecursion

	if prio == dontMutate {
		return
	}

	_, isArrayTyp := typ.(*ArrayType)
	_, isBufferTyp := typ.(*BufferType)
	if !isBufferTyp && !isArrayTyp && arg.Dir() == DirOut || !typ.Varlen() && typ.Size() == 0 {
		return
	}

	if len(ma.args) == 0 {
		ma.args = ma.argsBuffer[:0]
	}
	ma.prioSum += prio
	ma.args = append(ma.args, mutationArg{arg, *ctx, ma.prioSum})
}

// enumerate every args, including subargs
func (ma *mutationArgs) collectArgType(arg Arg, ctx *ArgCtx) {
	ma.ignoreSpecial = false

	typ := arg.Type()
	// we may skip some pointer inside this arg.
	prio, _ := collectTypePrio(arg, ma.target)

	if prio == dontMutate {
		return
	}

	_, isArrayTyp := typ.(*ArrayType)
	_, isBufferTyp := typ.(*BufferType)
	if !isBufferTyp && !isArrayTyp && arg.Dir() == DirOut || !typ.Varlen() && typ.Size() == 0 {
		return
	}

	if len(ma.args) == 0 {
		ma.args = ma.argsBuffer[:0]
	}
	ma.prioSum += prio
	ma.args = append(ma.args, mutationArg{arg, *ctx, ma.prioSum})
}

func (ma *mutationArgs) chooseArg(r *rand.Rand) (Arg, ArgCtx) {
	goal := ma.prioSum * r.Float64()
	chosenIdx := sort.Search(len(ma.args), func(i int) bool { return ma.args[i].priority >= goal })
	arg := ma.args[chosenIdx]
	return arg.arg, arg.ctx
}

func (ma *mutationArgs) chooseFlagArg(r *rand.Rand) (Arg, ArgCtx) {
	goal := ma.prioSum * r.Float64()
	chosenIdx := sort.Search(len(ma.args), func(i int) bool { return ma.args[i].priority >= goal })
	arg := ma.args[chosenIdx]
	return arg.arg, arg.ctx
}

// TODO: find a way to estimate optimal priority values.
// Assign a priority for each type. The boolean is the reference type and it has
// the minimum priority, since it has only two possible values.
func (t *IntType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	// For a integer without a range of values, the priority is based on
	// the number of bits occupied by the underlying type.
	plainPrio := math.Log2(float64(t.TypeBitSize())) + 0.1*maxPriority
	if t.Kind != IntRange {
		return plainPrio, false
	}

	size := t.RangeEnd - t.RangeBegin + 1
	if t.Align != 0 {
		if t.RangeBegin == 0 && int64(t.RangeEnd) == -1 {
			// Special [0:-1] range for all possible values.
			size = (1<<t.TypeBitSize()-1)/t.Align + 1
		} else {
			size = (t.RangeEnd-t.RangeBegin)/t.Align + 1
		}
	}
	switch {
	case size <= 15:
		// For a small range, we assume that it is effectively
		// similar with FlagsType and we need to try all possible values.
		prio = rangeSizePrio(size)
	case size <= 256:
		// We consider that a relevant range has at most 256
		// values (the number of values that can be represented on a byte).
		prio = maxPriority
	default:
		// Ranges larger than 256 are equivalent with a plain integer.
		prio = plainPrio
	}
	return prio, false
}

func (t *StructType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if target.SpecialTypes[t.Name()] == nil || ignoreSpecial {
		return dontMutate, false
	}
	return maxPriority, true
}

func (t *UnionType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if target.SpecialTypes[t.Name()] == nil && len(t.Fields) == 1 || ignoreSpecial {
		return dontMutate, false
	}
	// For a non-special type union with more than one option
	// we mutate the union itself and also the value of the current option.
	if target.SpecialTypes[t.Name()] == nil {
		return maxPriority, false
	}
	return maxPriority, true
}

func (t *FlagsType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	prio = rangeSizePrio(uint64(len(t.Vals)))
	if t.BitMask {
		// We want a higher priority because the mutation will include
		// more possible operations (bitwise operations).
		prio += 0.1 * maxPriority
	}
	return prio, false
}

// Assigns a priority based on the range size.
func rangeSizePrio(size uint64) (prio float64) {
	switch size {
	case 0:
		prio = dontMutate
	case 1:
		prio = minPriority
	default:
		// Priority proportional with the number of values. After a threshold, the priority is constant.
		// The threshold is 15 because most of the calls have <= 15 possible values for a flag.
		prio = math.Min(float64(size)/3+0.4*maxPriority, 0.9*maxPriority)
	}
	return prio
}

func (t *PtrType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if arg.(*PointerArg).IsSpecial() {
		// TODO: we ought to mutate this, but we don't have code for this yet.
		return dontMutate, false
	}
	return 0.3 * maxPriority, false
}

func (t *ConstType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return dontMutate, false
}

func (t *CsumType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return dontMutate, false
}

func (t *ProcType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return 0.5 * maxPriority, false
}

func (t *ResourceType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return 0.5 * maxPriority, false
}

func (t *VmaType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	return 0.5 * maxPriority, false
}

func (t *LenType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	// Mutating LenType only produces "incorrect" results according to descriptions.
	return 0.1 * maxPriority, false
}

func (t *BufferType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if arg.Dir() == DirOut && !t.Varlen() {
		return dontMutate, false
	}
	if t.Kind == BufferString && len(t.Values) == 1 {
		// These are effectively consts (and frequently file names).
		return dontMutate, false
	}
	return 0.8 * maxPriority, false
}

func (t *ArrayType) getMutationPrio(target *Target, arg Arg, ignoreSpecial bool) (prio float64, stopRecursion bool) {
	if t.Kind == ArrayRangeLen && t.RangeBegin == t.RangeEnd {
		return dontMutate, false
	}
	return maxPriority, false
}

func mutateData(r *randGen, data []byte, minLen, maxLen uint64) []byte {
	for stop := false; !stop; stop = stop && r.oneOf(3) {
		f := mutateDataFuncs[r.Intn(len(mutateDataFuncs))]
		data, stop = f(r, data, minLen, maxLen)
	}
	return data
}

// The maximum delta for integer mutations.
const maxDelta = 35

var mutateDataFuncs = [...]func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool){
	// TODO(dvyukov): duplicate part of data.
	// Flip bit in byte.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 {
			return data, false
		}
		byt := r.Intn(len(data))
		bit := r.Intn(8)
		data[byt] ^= 1 << uint(bit)
		return data, true
	},
	// Insert random bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 || uint64(len(data)) >= maxLen {
			return data, false
		}
		n := r.Intn(16) + 1
		if r := int(maxLen) - len(data); n > r {
			n = r
		}
		pos := r.Intn(len(data))
		for i := 0; i < n; i++ {
			data = append(data, 0)
		}
		copy(data[pos+n:], data[pos:])
		for i := 0; i < n; i++ {
			data[pos+i] = byte(r.Int31())
		}
		if uint64(len(data)) > maxLen || r.bin() {
			data = data[:len(data)-n] // preserve original length
		}
		return data, true
	},
	// Remove bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if len(data) == 0 {
			return data, false
		}
		n := r.Intn(16) + 1
		if n > len(data) {
			n = len(data)
		}
		pos := 0
		if n < len(data) {
			pos = r.Intn(len(data) - n)
		}
		copy(data[pos:], data[pos+n:])
		data = data[:len(data)-n]
		if uint64(len(data)) < minLen || r.bin() {
			for i := 0; i < n; i++ {
				data = append(data, 0) // preserve original length
			}
		}
		return data, true
	},
	// Append a bunch of bytes.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		if uint64(len(data)) >= maxLen {
			return data, false
		}
		const max = 256
		n := max - r.biasedRand(max, 10)
		if r := int(maxLen) - len(data); n > r {
			n = r
		}
		for i := 0; i < n; i++ {
			data = append(data, byte(r.rand(256)))
		}
		return data, true
	},
	// Replace int8/int16/int32/int64 with a random value.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		storeInt(data[i:], r.Uint64(), width)
		return data, true
	},
	// Add/subtract from an int8/int16/int32/int64.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		v := loadInt(data[i:], width)
		delta := r.rand(2*maxDelta+1) - maxDelta
		if delta == 0 {
			delta = 1
		}
		if r.oneOf(10) {
			v = swapInt(v, width)
			v += delta
			v = swapInt(v, width)
		} else {
			v += delta
		}
		storeInt(data[i:], v, width)
		return data, true
	},
	// Set int8/int16/int32/int64 to an interesting value.
	func(r *randGen, data []byte, minLen, maxLen uint64) ([]byte, bool) {
		width := 1 << uint(r.Intn(4))
		if len(data) < width {
			return data, false
		}
		i := r.Intn(len(data) - width + 1)
		value := r.randInt64()
		if r.oneOf(10) {
			value = swap64(value)
		}
		storeInt(data[i:], value, width)
		return data, true
	},
}

func swap16(v uint16) uint16 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v = 0
	v |= uint16(v1) << 0
	v |= uint16(v0) << 8
	return v
}

func swap32(v uint32) uint32 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v2 := byte(v >> 16)
	v3 := byte(v >> 24)
	v = 0
	v |= uint32(v3) << 0
	v |= uint32(v2) << 8
	v |= uint32(v1) << 16
	v |= uint32(v0) << 24
	return v
}

func swap64(v uint64) uint64 {
	v0 := byte(v >> 0)
	v1 := byte(v >> 8)
	v2 := byte(v >> 16)
	v3 := byte(v >> 24)
	v4 := byte(v >> 32)
	v5 := byte(v >> 40)
	v6 := byte(v >> 48)
	v7 := byte(v >> 56)
	v = 0
	v |= uint64(v7) << 0
	v |= uint64(v6) << 8
	v |= uint64(v5) << 16
	v |= uint64(v4) << 24
	v |= uint64(v3) << 32
	v |= uint64(v2) << 40
	v |= uint64(v1) << 48
	v |= uint64(v0) << 56
	return v
}

func swapInt(v uint64, size int) uint64 {
	switch size {
	case 1:
		return v
	case 2:
		return uint64(swap16(uint16(v)))
	case 4:
		return uint64(swap32(uint32(v)))
	case 8:
		return swap64(v)
	default:
		panic(fmt.Sprintf("swapInt: bad size %v", size))
	}
}

func loadInt(data []byte, size int) uint64 {
	switch size {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(data))
	case 4:
		return uint64(binary.LittleEndian.Uint32(data))
	case 8:
		return binary.LittleEndian.Uint64(data)
	default:
		panic(fmt.Sprintf("loadInt: bad size %v", size))
	}
}

func storeInt(data []byte, v uint64, size int) {
	switch size {
	case 1:
		data[0] = uint8(v)
	case 2:
		binary.LittleEndian.PutUint16(data, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(data, uint32(v))
	case 8:
		binary.LittleEndian.PutUint64(data, v)
	default:
		panic(fmt.Sprintf("storeInt: bad size %v", size))
	}
}

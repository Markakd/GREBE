// errorcheck

// Copyright 2013 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package p

func f() {
	var a [10]int
	_ = a[-1]  // ERROR "invalid array index -1|index out of bounds"
	_ = a[-1:] // ERROR "invalid slice index -1|index out of bounds"
	_ = a[:-1] // ERROR "invalid slice index -1|index out of bounds"
	_ = a[10]  // ERROR "invalid array index 10|index out of bounds"

	var s []int
	_ = s[-1]  // ERROR "invalid slice index -1|index out of bounds"
	_ = s[-1:] // ERROR "invalid slice index -1|index out of bounds"
	_ = s[:-1] // ERROR "invalid slice index -1|index out of bounds"
	_ = s[10]

	const c = "foo"
	_ = c[-1]  // ERROR "invalid string index -1|index out of bounds"
	_ = c[-1:] // ERROR "invalid slice index -1|index out of bounds"
	_ = c[:-1] // ERROR "invalid slice index -1|index out of bounds"
	_ = c[3]   // ERROR "invalid string index 3|index out of bounds"

	var t string
	_ = t[-1]  // ERROR "invalid string index -1|index out of bounds"
	_ = t[-1:] // ERROR "invalid slice index -1|index out of bounds"
	_ = t[:-1] // ERROR "invalid slice index -1|index out of bounds"
	_ = t[3]
}

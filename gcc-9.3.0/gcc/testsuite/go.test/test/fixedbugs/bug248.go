// $G $D/$F.dir/bug0.go &&
// $G $D/$F.dir/bug1.go &&
// $G $D/$F.dir/bug2.go &&
// errchk $G -e $D/$F.dir/bug3.go &&
// $L bug2.$A &&
// ./$A.out || echo BUG: failed to compile

// NOTE: This test is not run by 'run.go' and so not run by all.bash.
// To run this test you must use the ./run shell script.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

ignored

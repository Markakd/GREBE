// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Fake network poller for NaCl and wasm/js.
// Should never be used, because NaCl and wasm/js network connections do not honor "SetNonblock".

// +build nacl js,wasm

package runtime

func netpollinit() {
}

func netpolldescriptor() uintptr {
	return ^uintptr(0)
}

func netpollopen(fd uintptr, pd *pollDesc) int32 {
	return 0
}

func netpollclose(fd uintptr) int32 {
	return 0
}

func netpollarm(pd *pollDesc, mode int) {
}

func netpoll(block bool) gList {
	return gList{}
}

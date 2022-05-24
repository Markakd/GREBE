// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

import "unsafe"

func (ts *Timestruc) Unix() (sec int64, nsec int64) {
	return int64(ts.Sec), int64(ts.Nsec)
}

func (ts *Timestruc) Nano() int64 {
	return int64(ts.Sec)*1e9 + int64(ts.Nsec)
}

func direntIno(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Ino), unsafe.Sizeof(Dirent{}.Ino))
}

func direntReclen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Reclen), unsafe.Sizeof(Dirent{}.Reclen))
}

func direntNamlen(buf []byte) (uint64, bool) {
	reclen, ok := direntReclen(buf)
	if !ok {
		return 0, false
	}
	return reclen - uint64(unsafe.Offsetof(Dirent{}.Name)), true
}

//sysnb getexecname() (execname unsafe.Pointer, err error)
//getexecname() *byte

func Getexecname() (path string, err error) {
	ptr, err := getexecname()
	if err != nil {
		return "", err
	}
	bytes := (*[1 << 29]byte)(ptr)[:]
	for i, b := range bytes {
		if b == 0 {
			return string(bytes[:i]), nil
		}
	}
	panic("unreachable")
}

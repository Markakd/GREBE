! Test alternate entry points for functions when the result types
! of all entry points match

	function f1 (a)
	integer a, f1, e1
	f1 = 15 + a
	return
	entry e1
	e1 = 42
	end function
	function f2 ()
	real f2, e2
	entry e2
	e2 = 45
	end function

	program entrytest
	integer f1, e1
	real f2, e2
	if (f1 (6) .ne. 21) STOP 1
	if (e1 () .ne. 42) STOP 2
	if (f2 () .ne. 45) STOP 3
	if (e2 () .ne. 45) STOP 4
	end

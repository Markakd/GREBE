// { dg-do compile }

void foo()
{
  int i, j;

  #pragma omp for
  for (i = 0; i < 10; ++i)
    break;			// { dg-error "break" }

  bad1:				// { dg-error "jump to label" }
  #pragma omp for
  for (i = 0; i < 10; ++i)
    goto bad1;			// { dg-message "from here|exits OpenMP" }

  goto bad2;			// { dg-message "from here" }
  #pragma omp for
  for (i = 0; i < 10; ++i)
    {
      bad2: ;			// { dg-error "jump" }
                                // { dg-message "enters OpenMP" "" { target *-*-* } .-1 }
    }

  #pragma omp for
  for (i = 0; i < 10; ++i)
    for (j = 0; j < 10; ++j)
      if (i == j)
	break;

  #pragma omp for
  for (i = 0; i < 10; ++i)
    continue;
}

// { dg-message "error: invalid branch to/from OpenMP structured block" "" { target *-*-* } 14 }
// { dg-message "error: invalid entry to OpenMP structured block" "" { target *-*-* } 16 }

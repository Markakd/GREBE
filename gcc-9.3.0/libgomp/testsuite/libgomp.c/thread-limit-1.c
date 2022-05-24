/* { dg-do run } */
/* { dg-set-target-env-var OMP_THREAD_LIMIT "6" } */

#include <stdlib.h>
#include <unistd.h>
#include <omp.h>

int
main ()
{
  if (omp_get_thread_limit () != 6)
    return 0;
  omp_set_dynamic (0);
  omp_set_nested (1);
  #pragma omp parallel num_threads (3)
  if (omp_get_num_threads () != 3)
    abort ();
  #pragma omp parallel num_threads (3)
  if (omp_get_num_threads () != 3)
    abort ();
  #pragma omp parallel num_threads (8)
  if (omp_get_num_threads () > 6)
    abort ();
  #pragma omp parallel num_threads (6)
  if (omp_get_num_threads () != 6)
    abort ();
  int cnt = 0;
  #pragma omp parallel num_threads (5)
  #pragma omp parallel num_threads (5)
  #pragma omp parallel num_threads (2)
  {
    int v;
    #pragma omp atomic capture
    v = ++cnt;
    if (v > 6)
      abort ();
    usleep (10000);
    #pragma omp atomic
    --cnt;
  }
  return 0;
}

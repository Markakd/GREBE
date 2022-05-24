/* { dg-shouldfail "tsan" } */
/* { dg-additional-options "-ldl" } */

#include <pthread.h>
#include <unistd.h>
#include "tsan_barrier.h"

static pthread_barrier_t barrier;
int X = 0;

void MySleep() {
  sleep(1);
}

void *Thread(void *p) {
  barrier_wait(&barrier);
  MySleep();  // Assume the main thread has done the write.
  X = 42;
  return 0;
}

int main() {
  barrier_init(&barrier, 2);
  pthread_t t;
  pthread_create(&t, 0, Thread, 0);
  X = 43;
  barrier_wait(&barrier);
  pthread_join(t, 0);
  return 0;
}

/* { dg-output "WARNING: ThreadSanitizer: data race.*(\n|\r\n|\r).*} */
/* { dg-output "  As if synchronized via sleep:(\n|\r\n|\r)} */
/* { dg-output "         #0 sleep.*"*} */
/* { dg-output "         #1 MySleep.*"*} */
/* { dg-output "         #2 Thread.*"*} */

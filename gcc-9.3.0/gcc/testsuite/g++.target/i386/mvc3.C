/* { dg-do compile } */
/* { dg-require-ifunc "" } */

__attribute__((target("avx")))
__attribute__((target_clones("avx","arch=slm","default")))
int foo (); /* { dg-warning "'target_clones' attribute ignored due to conflict with 'target' attribute" } */

__attribute__((always_inline,target_clones("avx","arch=slm","default")))
int bar (); /* { dg-warning "'target_clones' attribute ignored due to conflict with 'always_inline' attribute" } */

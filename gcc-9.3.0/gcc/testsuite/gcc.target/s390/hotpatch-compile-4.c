/* Functional tests for the function hotpatching feature.  */

/* { dg-do compile } */
/* { dg-options "-O3 -mzarch -mhotpatch=0,0,0" } */
/* { dg-error "arguments to .-mhotpatch=n,m. should be non-negative integers" "" { target *-*-* } 0 } */

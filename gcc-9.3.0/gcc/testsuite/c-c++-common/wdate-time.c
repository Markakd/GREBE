/* { dg-do compile } */
/* { dg-options "-Wdate-time" } */

const char time[] = __TIME__;  /* { dg-warning "might prevent reproducible builds" }  */
const char date[] = __DATE__;  /* { dg-warning "might prevent reproducible builds" }  */
const char timestamp[] = __TIMESTAMP__;  /* { dg-warning "might prevent reproducible builds" }  */

/* Copyright (C) 2000 Free Software Foundation, Inc.  */

/* { dg-do preprocess } */
/* { dg-options "-std=iso9899:199409 -pedantic" } */

/* This file is for testing the preprocessor in -std=iso9899:199409
   -pedantic mode.  Neil Booth, 2 Dec 2000.  */

#if 1LL				/* { dg-warning "long long" } */
#endif

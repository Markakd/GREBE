/* { dg-do compile } */
/* { dg-options "-mcmse -mfloat-abi=soft" }  */
/* { dg-skip-if "Do not combine float-abi= hard | soft | softfp" {*-*-*} {"-mfloat-abi=hard" -mfloat-abi=softfp } {""} } */

#include "../../cmse-5.x"

/* { dg-final { scan-assembler "mov\tr1, lr" } } */
/* { dg-final { scan-assembler "mov\tr2, lr" } } */
/* { dg-final { scan-assembler "mov\tr3, lr" } } */
/* { dg-final { scan-assembler "mov\tip, lr" } } */
/* { dg-final { scan-assembler-not "vmov" } } */
/* { dg-final { scan-assembler-not "vmsr" } } */
/* { dg-final { scan-assembler "msr\tAPSR_nzcvq, lr" { target { ! arm_dsp } } } } */
/* { dg-final { scan-assembler "msr\tAPSR_nzcvqg, lr" { target arm_dsp } } } */
/* { dg-final { scan-assembler "bxns" } } */


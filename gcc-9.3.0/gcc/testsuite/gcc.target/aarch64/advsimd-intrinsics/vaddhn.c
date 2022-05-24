#include <arm_neon.h>
#include "arm-neon-ref.h"
#include "compute-ref-data.h"

#if defined(__cplusplus)
#include <cstdint>
#else
#include <stdint.h>
#endif

#define INSN_NAME vaddhn
#define TEST_MSG "VADDHN"

/* Expected results.  */
VECT_VAR_DECL(expected,int,8,8) [] = { 0x32, 0x32, 0x32, 0x32,
				       0x32, 0x32, 0x32, 0x32 };
VECT_VAR_DECL(expected,int,16,4) [] = { 0x32, 0x32, 0x32, 0x32 };
VECT_VAR_DECL(expected,int,32,2) [] = { 0x18, 0x18 };
VECT_VAR_DECL(expected,uint,8,8) [] = { 0x3, 0x3, 0x3, 0x3,
					0x3, 0x3, 0x3, 0x3 };
VECT_VAR_DECL(expected,uint,16,4) [] = { 0x37, 0x37, 0x37, 0x37 };
VECT_VAR_DECL(expected,uint,32,2) [] = { 0x3, 0x3 };

#include "vXXXhn.inc"

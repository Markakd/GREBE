#include <arm_neon.h>
#include "arm-neon-ref.h"
#include "compute-ref-data.h"

#define INSN_NAME vqdmlal
#define TEST_MSG "VQDMLAL"

/* Expected values of cumulative_saturation flag.  */
int VECT_VAR(expected_cumulative_sat,int,32,4) = 0;
int VECT_VAR(expected_cumulative_sat,int,64,2) = 0;

/* Expected results.  */
VECT_VAR_DECL(expected,int,32,4) [] = { 0x7c1e, 0x7c1f, 0x7c20, 0x7c21 };
VECT_VAR_DECL(expected,int,64,2) [] = { 0x7c1e, 0x7c1f };

/* Expected values of cumulative_saturation flag when saturation
   occurs.  */
int VECT_VAR(expected_cumulative_sat2,int,32,4) = 1;
int VECT_VAR(expected_cumulative_sat2,int,64,2) = 1;

/* Expected results when saturation occurs.  */
VECT_VAR_DECL(expected2,int,32,4) [] = { 0x7fffffef, 0x7ffffff0,
					 0x7ffffff1, 0x7ffffff2 };
VECT_VAR_DECL(expected2,int,64,2) [] = { 0x7fffffffffffffef,
					 0x7ffffffffffffff0 };

#include "vqdmlXl.inc"

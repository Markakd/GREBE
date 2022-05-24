// { dg-do compile { target c++11 } }
// Ignore warning on some powerpc-ibm-aix configurations.
// { dg-prune-output "non-standard ABI extension" }
// { dg-prune-output "changes the ABI" }

typedef float __attribute__ ((vector_size (4 * sizeof (float)))) V4;
constexpr V4 build (float x, float y, float z) { return __extension__ (V4){ x, y, z, 0 };}
constexpr V4 x = build (1, 0, 0);

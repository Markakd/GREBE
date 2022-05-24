#ifndef _COMMON_H
#define _COMMON_H

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>

#include <unistd.h>
#include <bitset>
#include <chrono>

using namespace llvm;
extern cl::list<std::string> InputFilenames;
extern cl::opt<unsigned> VerboseLevel;

#define KA_LOGS(lv, stmt)							\
	do {											\
		if (VerboseLevel >= lv)						\
			errs() << stmt;					\
	} while(0)

#define KA_LOGV(lv, v)							\
	do {											\
		if (VerboseLevel >= lv) {						\
			v->print(errs());					\
            errs() << "\n";                 \
        }                                   \
	} while(0)

#define RES_REPORT(stmt) KA_LOGS(0, stmt);
#define WARNING(stmt) KA_LOGS(1, "\n[WARN] " << stmt);
#define TEST_REPORT(stmt) KA_LOGS(3, "[TEST] " << stmt);

#define KA_ERR(stmt)															\
	do {																		\
		errs() << "ERROR (" << __FUNCTION__ << "@" << __LINE__ << ")";	\
		errs() << ": " << stmt;											\
		exit(-1);																\
    } while(0)
#endif

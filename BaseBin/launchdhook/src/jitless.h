#include <dlfcn.h>
#include <sys/spawn.h>
#include "../systemhook/src/common.h"
#include "../_external/modules/litehook/src/litehook.h"

#define _mh_execute_header (const struct mach_header_64 *)dlsym(RTLD_DEFAULT, "_mh_execute_header")
#define MSHookFunction(addr, replace, origOut) \
    *origOut = (void *)addr; \
    litehook_rebind_symbol(_mh_execute_header, addr, replace, NULL);

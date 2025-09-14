#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/mman.h>

#include "machomerger_hook.h"
#include "dyld_jbinfo.h"
#include "dyld.h"

// When running a binary from a different platform (e.g. iOS binaries on tvOS dyld), dyld will refuse to map it

extern bool ORIG(_ZNK5dyld39MachOFile19loadableIntoProcessENS_8PlatformEPKc)();
bool HOOK(_ZNK5dyld39MachOFile19loadableIntoProcessENS_8PlatformEPKc)()
{
	return true;
}

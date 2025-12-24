#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <libjailbreak/jbclient_mach.h>

#include "dyld.h"
#include "dyld_jbinfo.h"

__attribute__((section("__DATA,__jbinfo"))) static char jbinfoSection[0x4000];
#define jbInfo ((struct dyld_jbinfo *)&jbinfoSection[0])

bool gDyldhookInitDone = false;

bool jbinfo_is_checked_in(void)
{
	return jbInfo->state == DYLD_STATE_CHECKED_IN;
}

char *jbinfo_get_jbroot(void)
{
	return jbInfo->jbRootPath;
}

void consume_tokenized_sandbox_extensions(char *sandboxExtensions)
{
	if (sandboxExtensions[0] == '\0') return;

	char *it = sandboxExtensions;
	char *last = sandboxExtensions;
	while (*(++it) != '\0') {
		if (*it == '|') {
			*it = '\0';
			sandbox_extension_consume(last);
			last = &it[1];
			*it = '|';
		}
	}
	sandbox_extension_consume(last);
}

void dyldhook_perform_checkin(void)
{
	struct jbserver_mach_msg_checkin_reply *replyPtr; // Only for sizeof macro

	char *jbRootPathPtr = &jbInfo->data[0];
	char *bootUUIDPtr = &jbInfo->data[sizeof(replyPtr->jbRootPath)];
	char *sandboxExtensionsPtr = &jbInfo->data[sizeof(replyPtr->jbRootPath)+sizeof(replyPtr->bootUUID)];

	// Tell jbserver (in launchd) that this process exists
	// This will, amongst other things, disable page validation, which allows instruction hooks to be applied later
	if (jbclient_mach_process_checkin(jbRootPathPtr, bootUUIDPtr, sandboxExtensionsPtr, &jbInfo->fullyDebugged) == 0) {
		consume_tokenized_sandbox_extensions(sandboxExtensionsPtr);
		jbInfo->jbRootPath = jbRootPathPtr;
		jbInfo->bootUUID = bootUUIDPtr;
		jbInfo->sandboxExtensions = sandboxExtensionsPtr;
		jbInfo->state = DYLD_STATE_CHECKED_IN;
	}
}

void dyldhook_init(uintptr_t kernelParams)
{
	// If we are in launchd, bail out
	if (getpid() == 1) {
		return;
	}

	// Walk kernelParams to get envp
	uintptr_t argc = *(uintptr_t *)(kernelParams + sizeof(void *));
	char **envp = (char **)(kernelParams + sizeof(void *) + sizeof(argc) + (sizeof(const char *) * argc) + sizeof(void *));

	// If DYLD_INSERT_LIBRARIES is not set or does not contain systemhook, bail out
	const char *insertLibrariesVar = _simple_getenv(envp, "DYLD_INSERT_LIBRARIES");
	if (!insertLibrariesVar) return;
	if (!strstr(insertLibrariesVar, "/systemhook.dylib")) return;
#if !DOPAMINE_HAS_KRW
    // If a process chose to exempt itself, bail out
    // Used by launchd when executing jbctl to enable JIT
    if (_simple_getenv(envp, "DOPAMINE_EXEMPT_DYLDHOOK") != NULL) {
        ((char *)insertLibrariesVar)[0] = '\0';
        return;
    }
    // FIXME: we don't have a systemwide posix_spawn/exec hook so instead we put a blacklist here
    // might probably just fix fork later, this is quite annoying workaround
    const char *processBlacklist[] = {
        "/bin/bash",
        "/bin/dash",
        "/bin/sh",
        "/bin/zsh",
        "/sbin/mount",
        "/usr/bin/login",
        "/usr/local/sbin/sshd",
        // Fix Sileo
        "/var/jb/bin/dash",
        "/var/jb/bin/sh",
    };
    char **argv = (char **)(kernelParams + sizeof(void *) + sizeof(argc));
    size_t blacklistCount = sizeof(processBlacklist) / sizeof(processBlacklist[0]);
    for (size_t i = 0; i < blacklistCount; i++) {
        if (!strcmp(processBlacklist[i], argv[0])) {
            ((char *)insertLibrariesVar)[0] = '\0';
            return;
        }
    }
    // Fix Sileo
    char *prefixesBlacklist[] = {
        "/var/jb/usr/bin",
        "/var/jb/bin",
    };
    size_t prefixesCount = sizeof(prefixesBlacklist) / sizeof(prefixesBlacklist[0]);
    for (size_t i = 0; i < prefixesCount; i++) {
        if (!strncmp(prefixesBlacklist[i], argv[0], strlen(prefixesBlacklist[i]))) {
            ((char *)insertLibrariesVar)[0] = '\0';
            return;
        }
    }
#endif

	// If all is well, do check-in right here before dyld_start!
	dyldhook_perform_checkin();
}

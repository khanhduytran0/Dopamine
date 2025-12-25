#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <libjailbreak/jbclient_mach.h>
#if !DOPAMINE_HAS_KRW
#include <libjailbreak/codesign.h>
#include <signal.h>
#define    PT_TRACE_ME    0    /* child declares it's being traced */
#define    PT_KILL        8    /* kill the child process */
#define    PT_DETACH    11    /* stop tracing a process */
#define PT_ATTACHEXC    14    /* attach to running process with signal exception */
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
#define WAIT_ANY (-1)
extern int __wait4(pid_t, int *, int , void *rusage);
#endif

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
    
    // FIXME: we don't have fork fix so instead we exclude CLI tools from hook
    char **apple = envp;
    while (*apple != NULL) { apple++; }
    const char *executablePath = _simple_getenv(&apple[1], "executable_path");
    char *prefixesBlacklist[] = {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/local/bin",
        "/var/jb/bin",
        "/var/jb/usr/bin",
    };
    size_t prefixesCount = sizeof(prefixesBlacklist) / sizeof(prefixesBlacklist[0]);
    for (size_t i = 0; i < prefixesCount; i++) {
        if (!strncmp(prefixesBlacklist[i], executablePath, strlen(prefixesBlacklist[i]))) {
            ((char *)insertLibrariesVar)[0] = '\0';
            return;
        }
    }
    char *suffixesBlacklist[] = {
        "/procursus/bin",
        "/procursus/usr/bin",
        "/sbin/sshd",
    };
    size_t suffixesCount = sizeof(suffixesBlacklist) / sizeof(suffixesBlacklist[0]);
    for (size_t i = 0; i < suffixesCount; i++) {
        if (strstr(executablePath, suffixesBlacklist[i])) {
            ((char *)insertLibrariesVar)[0] = '\0';
            return;
        }
    }
    
    // Fast path JIT enabling for unsandboxed processes
    uint32_t csFlags = 0;
    csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
    if (!(csFlags & CS_DEBUGGED)) {
        int pid = fork();
        if (pid == 0) {
            ptrace(PT_TRACE_ME, 0, 0, 0);
            kill(getpid(), SIGSTOP);
            return;
        } else if (pid > 0) {
            __wait4(pid, NULL, WUNTRACED, NULL);
            ptrace(PT_DETACH, pid, NULL, 0);
            kill(pid, SIGKILL);
        }
    }
#endif

	// If all is well, do check-in right here before dyld_start!
	dyldhook_perform_checkin();
}

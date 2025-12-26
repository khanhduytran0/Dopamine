#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>
#include <os/log.h>
#include <util.h>
#include "syscall.h"
#include "litehook.h"
#include <libjailbreak/jbclient_mach.h>
#if !DOPAMINE_HAS_KRW
#include <libjailbreak/jbclient_xpc.h>
kern_return_t litehook_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
#endif

extern void __fork(void);

int childToParentPipe[2];
int parentToChildPipe[2];
static void open_pipes(void)
{
	if (pipe(parentToChildPipe) < 0 || pipe(childToParentPipe) < 0) {
		abort();
	}
}
static void close_pipes(void)
{
	if (ffsys_close(parentToChildPipe[0]) != 0 || ffsys_close(parentToChildPipe[1]) != 0 || ffsys_close(childToParentPipe[0]) != 0 || ffsys_close(childToParentPipe[1]) != 0) {
		abort();
	}
}

#if !DOPAMINE_HAS_KRW
// https://github.com/roothide/Bootstrap-basebin/blob/537faa81c8ba791efedb4d151c375aa367556d66/bootstrap/fixfork.c#L536-L572
extern void* _dyld_get_shared_cache_range(size_t* length);
void collect_modified_pages(uint64_t *out, uint64_t *out_max)
{
    size_t dsc_length=0;
    void* dsc_start = _dyld_get_shared_cache_range(&dsc_length);
    
    natural_t depth = 1;
    vm_size_t region_size = 0;
    vm_address_t region_base = 0;
    
    while(true) {
        struct vm_region_submap_info_64 info={0};
        mach_msg_type_number_t info_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        
        kern_return_t kr = vm_region_recurse_64(mach_task_self(), &region_base, &region_size, &depth, (vm_region_info_t)&info, &info_cnt);
        if(kr != KERN_SUCCESS) break;
        if(info.is_submap != 0) {
            depth++;
        } else {
            if ((info.protection & VM_PROT_EXECUTE) &&
                (info.max_protection & VM_PROT_WRITE) &&
                info.share_mode == SM_COW &&
                (uint64_t)region_base >= (uint64_t)dsc_start &&
                (uint64_t)region_base < ((uint64_t)dsc_start+dsc_length)) {
                out[0] = region_base;
                out[1] = region_size;
                out += 2;
                // too many hooks should not happen, but just in case
                if (out >= out_max) abort();
            }
            region_base += region_size;
        }
    }
}
#endif

void child_fixup(void)
{
	// Tell parent we are waiting for fixup now
	char msg = ' ';
	ffsys_write(childToParentPipe[1], &msg, sizeof(msg));

	// Wait until parent completes fixup
	ffsys_read(parentToChildPipe[0], &msg, sizeof(msg));
}

void parent_fixup(pid_t childPid)
{
	// Wait until the child is ready and waiting
	char msg = ' ';
	ffsys_read(childToParentPipe[0], &msg, sizeof(msg));

	// Child is waiting for wx_allowed + permission fixups now
	// Apply fixup
#if DOPAMINE_HAS_KRW
	int64_t fix_ret = jbclient_mach_fork_fix(childPid);
	if (fix_ret != 0) {
		kill(childPid, SIGKILL);
		abort();
	}
#else
    if (ffsys_ptrace(PT_ATTACHEXC, childPid, 0, 0) == 0) {
        while (ffsys_ptrace(PT_DETACH, childPid, 0, 0) != 0) {}
    }
    ffsys_kill(childPid, SIGCONT);
#endif

	// Tell child we are done, this will make it resume
	ffsys_write(parentToChildPipe[1], &msg, sizeof(msg));
}

__attribute__((visibility ("default"))) pid_t forkfix___fork(void)
{
	open_pipes();

#if !DOPAMINE_HAS_KRW
    uint64_t modified_pages[1024*2] = {0};
    collect_modified_pages(modified_pages, modified_pages + 1024*2);
    for (int i = 0; i < 1024*2; i += 2) {
        if (modified_pages[i] == 0) break;
        litehook_vm_protect(mach_task_self(), modified_pages[i], modified_pages[i+1], false, VM_PROT_READ | VM_PROT_WRITE);
    }
#endif
	pid_t pid = ffsys_fork();
	if (pid < 0) {
		close_pipes();
		return pid;
	}

	if (pid == 0) {
		child_fixup();
        mach_thread_self(); // ensure thread port
        task_self_trap(); // ensure task port
	}
	else {
		parent_fixup(pid);
	}
#if !DOPAMINE_HAS_KRW
    for (int i = 0; i < 1024*2; i += 2) {
        if (modified_pages[i] == 0) break;
        litehook_vm_protect(task_self_trap(), modified_pages[i], modified_pages[i+1], false, VM_PROT_READ | VM_PROT_EXECUTE);
    }
#endif

	close_pipes();
	return pid;
}

void apply_fork_hook(void)
{
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		litehook_hook_function((void *)__fork, (void *)forkfix___fork);
	});
}

__attribute__((constructor)) static void initializer(void)
{
	apply_fork_hook();
}

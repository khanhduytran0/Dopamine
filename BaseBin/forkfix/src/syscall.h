kern_return_t ffsys_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
pid_t ffsys_fork(void);
pid_t ffsys_getpid(void);
int ffsys_pid_suspend(pid_t pid);

ssize_t ffsys_read(int fildes, void *buf, size_t nbyte);
ssize_t ffsys_write(int fildes, const void *buf, size_t nbyte);
int ffsys_close(int fildes);
#if !DOPAMINE_HAS_KRW
int ffsys___wait4(pid_t pid, int *status, int options, struct rusage *rusage);
int ffsys_ptrace(int request, pid_t pid, caddr_t addr, int data);
int ffsys_kill(pid_t pid, int sig);
#define    PT_TRACE_ME    0    /* child declares it's being traced */
#define PT_CONTINUE    7    /* continue the child */
#define    PT_KILL        8    /* kill the child process */
#define    PT_DETACH    11    /* stop tracing a process */
#define PT_ATTACHEXC    14    /* attach to running process with signal exception */
#endif

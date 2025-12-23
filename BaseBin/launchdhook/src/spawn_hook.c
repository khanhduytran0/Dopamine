#include <spawn.h>
#if DOPAMINE_HAS_KRW
#include "../systemhook/src/common.h"
#else
#include "jitless.h"
#include "spawn_internal.h"
#include <malloc/malloc.h>
#include <paths.h>    /* for _PATH_DEFPATH */
#endif
#include "boomerang.h"
#include "crashreporter.h"
#include "update.h"
#include <libjailbreak/util.h>
#if DOPAMINE_HAS_KRW
#include <substrate.h>
#endif
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include "jbserver/jbserver_local.h"
extern char **environ;

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern void systemwide_domain_set_enabled(bool enabled);

#define LOG_PROCESS_LAUNCHES 0

extern bool gInEarlyBoot;

void early_boot_done(void)
{
	gInEarlyBoot = false;
}

void ensure_fakelib_mounted(void)
{
	struct statfs fsb;
    if (statfs("/usr/lib", &fsb) != 0) return;
    if (strcmp(fsb.f_mntonname, "/usr/lib") != 0) {
		systemwide_domain_set_enabled(true);

		// The jailbreak server is not reachable at this point in the launchd lifecycle
		// So we need to host our own, just so that jbctl can talk to it
		mach_port_t serverPort = jbserver_local_start();
		jbctl_earlyboot(serverPort, "internal", "fakelib", "mount", NULL);
		jbserver_local_stop();

		// Note down that the jailbreak was hidden
		// So that after the userspace reboot, we can unmount fakelib again
		setenv("DOPAMINE_IS_HIDDEN", "1", true);
	}
}

int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	// we need to disable the crash reporter during the orig call
	// otherwise the child process inherits the exception ports
	// and this would trip jailbreak detections
	crashreporter_pause();	
	int r = __posix_spawn_orig(pid, path, desc, argv, envp);
	crashreporter_resume();

	return r;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	if (path) {
		char executablePath[1024];
		uint32_t bufsize = sizeof(executablePath);
		_NSGetExecutablePath(&executablePath[0], &bufsize);
		if (!strcmp(path, executablePath)) {
			// This spawn will perform a userspace reboot...
			// Instead of the ordinary hook, we want to reinsert this dylib
			// This has already been done in envp so we only need to call the original posix_spawn

			// We are back in "early boot" for the remainder of this launchd instance
			// Mainly so we don't lock up while spawning boomerang
			gInEarlyBoot = true;

			// If the jailbreak is currently hidden, fakelib is not mounted
			// It needs to be mounted to regain launchd code execution after the userspace reboot
			ensure_fakelib_mounted();

#if LOG_PROCESS_LAUNCHES
			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
			fprintf(f, "==== USERSPACE REBOOT ====\n");
			fclose(f);
#endif

#if DOPAMINE_HAS_KRW
			// Before the userspace reboot, we want to stash the primitives into boomerang
			boomerang_stashPrimitives();
#endif

			// Fix Xcode debugging being broken after the userspace reboot
			unmount("/Developer", MNT_FORCE);

			// If there is a pending jailbreak update, apply it now
			const char *stagedJailbreakUpdate = getenv("STAGED_JAILBREAK_UPDATE");
			if (stagedJailbreakUpdate) {
				int r = jbupdate_basebin(stagedJailbreakUpdate);
				if (r != 0) {
					char msg[1000];
					snprintf(msg, 1000, "Failed updating basebin (error %d).", r);
					abort_with_reason(7, 1, msg, 0);
				}
				unsetenv("STAGED_JAILBREAK_UPDATE");
			}

			// Always use environ instead of envp, as boomerang_stashPrimitives calls setenv
			// setenv / unsetenv can sometimes cause environ to get reallocated
			// In that case envp may point to garbage or be empty
			// Say goodbye to this process
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, environ);
		}
	}

#if LOG_PROCESS_LAUNCHES
	if (path) {
		FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		fprintf(f, "%s", path);
		int ai = 0;
		while (argv) {
			if (argv[ai]) {
				if (ai >= 1) {
					fprintf(f, " %s", argv[ai]);
				}
				ai++;
			}
			else {
				break;
			}
		}
		fprintf(f, "\n");
		fclose(f);

		// if (!strcmp(path, "/usr/libexec/xpcproxy")) {
		// 	const char *tmpBlacklist[] = {
		// 		"com.apple.logd"
		// 	};
		// 	size_t blacklistCount = sizeof(tmpBlacklist) / sizeof(tmpBlacklist[0]);
		// 	for (size_t i = 0; i < blacklistCount; i++)
		// 	{
		// 		if (!strcmp(tmpBlacklist[i], firstArg)) {
		// 			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		// 			fprintf(f, "blocked injection %s\n", firstArg);
		// 			fclose(f);
		// 			return __posix_spawn_orig_wrapper(pid, path, file_actions, desc, envp);
		// 		}
		// 	}
		// }
	}
#endif

	// We can't support injection into processes that get spawned before the launchd XPC server is up
	// (Technically we could but there is little reason to, since it requires additional work)
	if (gInEarlyBoot) {
		if (!strcmp(path, "/usr/libexec/xpcproxy")) {
			// The spawned process being xpcproxy indicates that the launchd XPC server is up
			// All processes spawned including this one should be injected into
			early_boot_done();
		}
		else {
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
		}
	}

	return posix_spawn_hook_shared(pid, path, desc, argv, envp, __posix_spawn_orig_wrapper, systemwide_trust_file_by_path, platform_set_process_debugged, jbsetting(jetsamMultiplier));
}
#if !DOPAMINE_HAS_KRW
int
posix_spawn_hook(pid_t * __restrict pid, const char * __restrict path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t * __restrict attrp,
    char *const argv[__restrict], char *const envp[__restrict])
{
    int saveerrno = errno;
    int ret = 0;
    struct _posix_spawn_args_desc ad;
    struct _posix_spawn_args_desc *adp = NULL;
    /*
     * Only do extra work if we have file actions or attributes to push
     * down.  We use a descriptor to push this information down, since we
     * want to have size information, which will let us (1) preallocate a
     * single chunk of memory for the copyin(), and (2) allow us to do a
     * single copyin() per attributes or file actions as a monlithic block.
     *
     * Note:    A future implementation may attempt to do the same
     *        thing for the argv/envp data, which could potentially
     *        result in a performance improvement due to increased
     *        kernel efficiency, even though it would mean copying
     *        the data in user space.
     */
    if ((file_actions != NULL && (*file_actions != NULL) && (*(_posix_spawn_file_actions_t *)file_actions)->psfa_act_count > 0) || attrp != NULL) {
        memset(&ad, 0, sizeof(ad));
        adp = &ad;
        if (attrp != NULL && *attrp != NULL) {
            _posix_spawnattr_t psattr = *(posix_spawnattr_t *)attrp;
            // https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c#L232
            ad.attr_size = malloc_size(*attrp) ?: sizeof(struct _posix_spawnattr);
            ad.attrp = psattr;

            if (psattr->psa_ports != NULL) {
                size_t psact_size = PS_PORT_ACTIONS_SIZE(psattr->psa_ports->pspa_count);
                if (psact_size == 0 && psattr->psa_ports->pspa_count != 0) {
                    errno = EINVAL;
                    ret = -1;
                    goto out;
                }
                ad.port_actions = psattr->psa_ports;
                ad.port_actions_size = psact_size;
            }
            if (psattr->psa_mac_extensions != NULL) {
                size_t macext_size = PS_MAC_EXTENSIONS_SIZE(psattr->psa_mac_extensions->psmx_count);
                if (macext_size == 0 && psattr->psa_mac_extensions->psmx_count != 0) {
                    errno = EINVAL;
                    ret = -1;
                    goto out;
                }
                ad.mac_extensions = psattr->psa_mac_extensions;
                ad.mac_extensions_size = macext_size;
            }
            if (psattr->psa_coalition_info != NULL) {
                ad.coal_info_size = sizeof(struct _posix_spawn_coalition_info);
                ad.coal_info = psattr->psa_coalition_info;
            }
            if (psattr->psa_persona_info != NULL) {
                ad.persona_info_size = sizeof(struct _posix_spawn_persona_info);
                ad.persona_info = psattr->psa_persona_info;
            }
            if (psattr->psa_posix_cred_info != NULL) {
                ad.posix_cred_info_size = sizeof(struct _posix_spawn_posix_cred_info);
                ad.posix_cred_info = psattr->psa_posix_cred_info;
            }
            if (psattr->psa_subsystem_root_path != NULL) {
                ad.subsystem_root_path_size = MAXPATHLEN;
                ad.subsystem_root_path = psattr->psa_subsystem_root_path;
            }
            if (psattr->psa_conclave_id != NULL) {
                ad.conclave_id_size = MAXCONCLAVENAME;
                ad.conclave_id = psattr->psa_conclave_id;
            }
        }
        if (file_actions != NULL && *file_actions != NULL) {
            _posix_spawn_file_actions_t psactsp =
                *(_posix_spawn_file_actions_t *)file_actions;

            if (psactsp->psfa_act_count > 0) {
                size_t fa_size = PSF_ACTIONS_SIZE(psactsp->psfa_act_count);
                if (fa_size == 0 && psactsp->psfa_act_count != 0) {
                    errno = EINVAL;
                    ret = -1;
                    goto out;
                }
                ad.file_actions_size = fa_size;
                ad.file_actions = psactsp;
            }
        }
    }

    //if (!posix_spawn_with_filter ||
    //    !posix_spawn_with_filter(pid, path, argv, envp, adp, &ret)) {
        ret = __posix_spawn_hook(pid, path, adp, argv, envp);
    //}

out:
    if (ret < 0) {
        ret = errno;
    }
    errno = saveerrno;
    return ret;
}
int
posix_spawnp_hook(pid_t * __restrict pid, const char * __restrict file,
        const posix_spawn_file_actions_t *file_actions,
        const posix_spawnattr_t * __restrict attrp,
        char *const argv[ __restrict], char *const envp[ __restrict])
{
    const char *env_path;
    char path_buf[PATH_MAX];
    char *bp, *np, *op, *p;
    char **memp;
    size_t ln, lp;
    int cnt;
    int err = 0;
    int eacces = 0;
    struct stat sb;

    /* If it's an absolute or relative path name, it's easy. */
    if (strchr(file, '/')) {
        bp = (char *)file;
        env_path = op = NULL;
        goto retry;
    }

    if ((env_path = getenv("PATH")) == NULL)
        env_path = _PATH_DEFPATH;

    bp = path_buf;

    /* If it's an empty path name, fail in the usual POSIX way. */
    if (*file == '\0')
        return (ENOENT);

    op = env_path;
    ln = strlen(file);
    while (op != NULL) {
        np = strchrnul(op, ':');

        /*
         * It's a SHELL path -- double, leading and trailing colons
         * mean the current directory.
         */
        if (np == op) {
            /* Empty component. */
            p = ".";
            lp = 1;
        } else {
            /* Non-empty component. */
            p = op;
            lp = np - op;
        }

        /* Advance to the next component or terminate after this. */
        if (*np == '\0')
            op = NULL;
        else
            op = np + 1;

        /*
         * If the path is too long complain.  This is a possible
         * security issue; given a way to make the path too long
         * the user may spawn the wrong program.
         */
        if (lp + ln + 2 > sizeof(path_buf)) {
            err = ENAMETOOLONG;
            goto done;
        }
        bcopy(p, path_buf, lp);
        path_buf[lp] = '/';
        bcopy(file, path_buf + lp + 1, ln);
        path_buf[lp + ln + 1] = '\0';

retry:        err = posix_spawn_hook(pid, bp, file_actions, attrp, argv, envp);
        switch (err) {
        case E2BIG:
        case ENOMEM:
        case ETXTBSY:
            goto done;
        case ELOOP:
        case ENAMETOOLONG:
        case ENOENT:
        case ENOTDIR:
            break;
        case ENOEXEC:
            for (cnt = 0; argv[cnt]; ++cnt)
                ;

            /*
             * cnt may be 0 above; always allocate at least
             * 3 entries so that we can at least fit "sh", bp, and
             * the NULL terminator.  We can rely on cnt to take into
             * account the NULL terminator in all other scenarios,
             * as we drop argv[0].
             */
            memp = alloca(MAX(3, cnt + 2) * sizeof(char *));
            if (memp == NULL) {
                /* errno = ENOMEM; XXX override ENOEXEC? */
                goto done;
            }
            if (cnt > 0) {
                memp[0] = argv[0];
                memp[1] = bp;
                bcopy(argv + 1, memp + 2, cnt * sizeof(char *));
            } else {
                memp[0] = "sh";
                memp[1] = bp;
                memp[2] = NULL;
            }
            err = posix_spawn_hook(pid, _PATH_BSHELL, file_actions, attrp, memp, envp);
            goto done;
        default:
            /*
             * EACCES may be for an inaccessible directory or
             * a non-executable file.  Call stat() to decide
             * which.  This also handles ambiguities for EFAULT
             * and EIO, and undocumented errors like ESTALE.
             * We hope that the race for a stat() is unimportant.
             */
            if (stat(bp, &sb) != 0)
                break;
            if (err == EACCES) {
                eacces = 1;
                continue;
            }
            goto done;
        }
    }
    if (eacces)
        err = EACCES;
    /* Preserve errno from posix_spawn(3) if it wasn't a PATH search. */
    else if (env_path != NULL)
        err = ENOENT;
done:
    return (err);
}
#endif

void initSpawnHooks(void)
{
#if DOPAMINE_HAS_KRW
	MSHookFunction(&__posix_spawn, (void *)__posix_spawn_hook, NULL);
#else
    const struct mach_header_64 *mainBinHeader = _mh_execute_header;
    litehook_rebind_symbol(mainBinHeader, posix_spawn, posix_spawn_hook, NULL);
    litehook_rebind_symbol(mainBinHeader, posix_spawnp, posix_spawnp_hook, NULL);
#endif
}

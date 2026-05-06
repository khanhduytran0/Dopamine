#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <spawn.h>
#include <string.h>
#import <IOKit/IOKitLib.h>
#include <limits.h>
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <sys/mount.h>
#include "mount_args.h"
#include <dirent.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/sysctl.h>

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);
int posix_spawnattr_set_launch_type_np(posix_spawnattr_t *attr, uint8_t launch_type);

int envbuf_find(const char *envp[], const char *name)
{
    if (envp) {
        unsigned long nameLen = strlen(name);
        int k = 0;
        const char *env = envp[k++];
        while (env) {
            unsigned long envLen = strlen(env);
            if (envLen > nameLen) {
                if (!strncmp(env, name, nameLen)) {
                    if (env[nameLen] == '=') {
                        return k-1;
                    }
                }
            }
            env = envp[k++];
        }
    }
    return -1;
}

int envbuf_len(const char *envp[])
{
    if (envp == NULL) return 1;

    int k = 0;
    const char *env = envp[k++];
    while (env) {
        env = envp[k++];
    }
    return k;
}

void envbuf_setenv(char **envpp[], const char *name, const char *value)
{
    if (envpp) {
        char **envp = *envpp;
        if (!envp) {
            // treat NULL as [NULL]
            envp = malloc(sizeof(const char *));
            envp[0] = NULL;
        }

        char *envToSet = malloc(strlen(name)+strlen(value)+2);
        strcpy(envToSet, name);
        strcat(envToSet, "=");
        strcat(envToSet, value);

        int existingEnvIndex = envbuf_find((const char **)envp, name);
        if (existingEnvIndex >= 0) {
            // if already exists: deallocate old variable, then replace pointer
            free(envp[existingEnvIndex]);
            envp[existingEnvIndex] = envToSet;
        }
        else {
            // if doesn't exist yet: increase env buffer size, place at end
            int prevLen = envbuf_len((const char **)envp);
            *envpp = realloc(envp, (prevLen+1)*sizeof(const char *));
            envp = *envpp;
            envp[prevLen-1] = envToSet;
            envp[prevLen] = NULL;
        }
    }
}

char **envbuf_mutcopy(const char *envp[])
{
    if (envp == NULL) return NULL;

    int len = envbuf_len(envp);
    char **envcopy = malloc(len * sizeof(char *));

    for (int i = 0; i < len-1; i++) {
        envcopy[i] = strdup(envp[i]);
    }
    envcopy[len-1] = NULL;

    return envcopy;
}
void envbuf_free(char *envp[])
{
    if (envp == NULL) return;

    int len = envbuf_len((const char**)envp);
    for (int i = 0; i < len-1; i++) {
        free(envp[i]);
    }
    free(envp);
}

int remountWritable(char *mntpoint)
{
    struct statfs ppStfs;
    int r = statfs(mntpoint, &ppStfs);
    if (r != 0) return r;
    
    uint32_t flags = MNT_UPDATE;
    struct hfs_mount_args mntargs =
    {
        .fspec = ppStfs.f_mntfromname,
        .hfs_mask = 0,
    };
    return mount("apfs", mntpoint, flags, &mntargs);
}


int disableMachFiltering(void)
{
    int value = 0;

    return sysctlbyname("security.mac.sandbox.message_filter.mach_filtering_enabled",
                     NULL,
                     NULL,
                     &value,
                     sizeof(value));
}

int main(int argc, char* argv[], char* envp[]) {
    char launchdhookPath[PATH_MAX];
    char fakelibPath[PATH_MAX];
    sprintf(launchdhookPath, "/var/jb/basebin/launchdhook.dylib");
    
    char *activePrebootPath = "/";
    char randomizedJailbreakPath[PATH_MAX];
    
    // Find jailbreak root, look for Dopamine 2.x path
    DIR *d = opendir(activePrebootPath);
    assert(d != NULL);
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if(!strncmp(dir->d_name, "dopamine", 8)) {
            snprintf(randomizedJailbreakPath, sizeof(randomizedJailbreakPath), "%s%s/procursus", activePrebootPath, dir->d_name);
            break;
        }
    }
    closedir(d);
    snprintf(launchdhookPath, sizeof(launchdhookPath), "%s/basebin/launchdhook.dylib", randomizedJailbreakPath);
    
    
    remountWritable("/");
    remountWritable("/private/preboot");
    disableMachFiltering();
    
    
    snprintf(fakelibPath, sizeof(fakelibPath), "%s/basebin/.fakelib", randomizedJailbreakPath);
    if (mount("bindfs", "/usr/lib", MNT_RDONLY, (void *)fakelibPath) != 0) {
        char msg[4000];
        snprintf(msg, 4000, "Dopamine: Failed to mount fakelib /usr/lib -> %s: %s. Cannot continue", fakelibPath, strerror(errno));
        abort_with_reason(7, 1, msg, 0);
    }
    
    char **envc = envbuf_mutcopy((const char **)envp);
    pid_t *pid = 0;
    envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", launchdhookPath);
    envbuf_setenv(&envc, "XPC_USERSPACE_REBOOTED", "1"); // makes dyld not graft again
    if (access("/usr/appleinternal/sbin/launchd.development", F_OK) == 0 &&
        access("/usr/appleinternal/sbin/.force_release_launchd", F_OK) != 0) {
        argv[0] = "/usr/appleinternal/sbin/launchd.development";
    } else {
        argv[0] = "/sbin/launchd";
    }
    
    posix_spawnattr_t attrp;
    posix_spawnattr_init(&attrp);
    posix_spawnattr_set_launch_type_np(&attrp, 1);
    posix_spawnattr_setflags(&attrp, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_CLOEXEC_DEFAULT);
    posix_spawn(pid, argv[0], NULL, &attrp, argv, envc);
    envbuf_free(envc);
}

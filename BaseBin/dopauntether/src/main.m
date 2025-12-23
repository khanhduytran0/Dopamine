#import <Foundation/Foundation.h>
#include <dirent.h>
#include <dlfcn.h>
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
#include <sys/types.h>
#include <copyfile.h>
#import <mach/mach.h>
#import <pthread.h>
#import <sys/sysctl.h>

// This library serves as a replacement to /usr/lib/libsandbox.1.dylib in launchd as it does not have enough load commands
__attribute__((constructor)) static void initializer(void)
{
    char launchdhookPath[PATH_MAX];
    sprintf(launchdhookPath, "/var/jb/basebin/launchdhook.dylib");
    
    // We cannot directly link against launchdhook as /private/preboot is not yet mounted before ignition starts(?)
    // Also this allows jailbreak to be disabled entirely by just removing the symlink
    if (!getenv("XPC_USERSPACE_REBOOTED")) {
        char *activePrebootPath = "/private/preboot/Cryptexes";
        char randomizedJailbreakPath[PATH_MAX];
        
        // Find jailbreak root, look for Dopamine 2.x path
        DIR *d = opendir(activePrebootPath);
        assert(d != NULL);
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if(!strncmp(dir->d_name, "dopamine", 8)) {
                snprintf(randomizedJailbreakPath, sizeof(randomizedJailbreakPath), "%s/%s/procursus", activePrebootPath, dir->d_name);
                break;
            }
        }
        closedir(d);
        snprintf(launchdhookPath, sizeof(launchdhookPath), "%s/basebin/launchdhook.dylib", randomizedJailbreakPath);
    }
    
    printf("dopauntether: Loading launchdhook from %s\n", launchdhookPath);
    void *handle = dlopen(launchdhookPath, RTLD_GLOBAL);
    printf("dopauntether: Loaded launchdhook handle: %p\n", handle);
    if (!handle) {
        printf("%s", dlerror());
    } else {
        printf("%s\n", "                                                                                                    ");
        printf("%s\n", "                                                                                                    ");
        printf("%s\n", "                            @@@:  +@@-                                                              ");
        printf("%s\n", "                            ...*@@-...                                                              ");
        printf("%s\n", "                               *@@:                                                                 ");
        printf("%s\n", "                  .@@@   @@@.  *@@:  =@@+  .@@@                                                     ");
        printf("%s\n", "                  .@@@   @@@.  *@@:  =@@+  .@@@                                                     ");
        printf("%s\n", "                  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                                     ");
        printf("%s\n", "                  .%%%@@@@@@@@@@@@@@@@@@@@@@%%%                                                     ");
        printf("%s\n", "                      @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "                      @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "                      @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "                         @@@@@@@@@@@@@@@+                                                           ");
        printf("%s\n", "                         @@@@@@@@@@@@@@@+                                                           ");
        printf("%s\n", "                         @@@@@@@@@@@@@@@+                                                           ");
        printf("%s\n", "                         @@@@@@@@@@@@@@@+                                                           ");
        printf("%s\n", "                         @@@@@@@@@@@@@@@+                                                           ");
        printf("%s\n", "                      @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "                      @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "               :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                                  ");
        printf("%s\n", "               :%%%%%%@@@@@@@@@@@@@@@@@@@@@@%%%%%%                                                  ");
        printf("%s\n", "                      @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "                      @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "                      @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "@@@@@@                @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "@@@@@@                @@@@@@@@@@@@@@@@@@@@@%                                                        ");
        printf("%s\n", "@@@@@@@@@@@@@@@#      @@@@@@@@@@@@@@@@@@@@@%                  -@@+                                  ");
        printf("%s\n", "@@@@@@===%@@@@@%=====-@@@@@@@@@@@@@@@@@@@@@%                  -@@+                  -=====-         ");
        printf("%s\n", "@@@@@@   %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                  -@@+                  #@@@@@%         ");
        printf("%s\n", "@@@   @@@.  *@@#  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#         @@@@@@@@@*            ");
        printf("%s\n", "@@@   @@@.  *@@#  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*         @@@@@@@@@*            ");
        printf("%s\n", "@@@@@@   %@@-  :@@@   @@@@@@@@@@@@@@@@@@@@@%  .@@@   @@@.  +@@+  :@@@@@@@@@@@@@@@.  #@@@@@%         ");
        printf("%s\n", "@@@###:::*##-::-###:::@@@@@@@@@@@@@@@@@@@@@%:::###:::###:::+@@+  :###############.  #@@%##*   :::   ");
        printf("%s\n", "@@@   @@@.  *@@#  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@.  %@@@@@+                     #@@*      @@@   ");
        printf("%s\n", "@@@%%%:::#%%-::-%%#:::@@@@@@@@@@@@@@@@@@@@@%:::%%%:::%%%:::+@@+                     #@@@%%%%%%@@@%%%");
        printf("%s\n", "@@@@@@   %@@-  :@@@   @@@@@@@@@@@@@@@@@@@@@%  .@@@   @@@.  +@@+                     #@@@@@@@@@@@@@@@");
        printf("%s\n", "@@@   @@@.  *@@#  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@.  %@@@@@+                     #@@*      @@@   ");
        printf("%s\n", "@@@   @@@.  *@@#  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@.  %@@@@@+                     #@@*      @@@   ");
        printf("%s\n", "@@@@@@   %@@-  :@@@   @@@@@@@@@@@@@@@@@@@@@%  .@@@   @@@.  +@@=  :@@@@@@@@@@@@@@@.  #@@@@@%         ");
        printf("%s\n", "@@@+++:::+++-::-+++:::@@@@@@@@@@@@@@@@@@@@@%:::@@@:::@@@-::*@@*::=@@%+++++++++@@@-::%@@%+++         ");
        printf("%s\n", "@@@   @@@.  *@@#  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*         @@@@@@@@@*            ");
        printf("%s\n", "@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               -@@+                  #@@@@@@         ");
        printf("%s\n", "@@@@@@   %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               -@@+                  #@@@@@%         ");
        printf("%s\n", "@@@@@@@@@@@@@@@#  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@               -@@+                                  ");
        printf("%s\n", "@@@@@@%%%%%%%%%#  .@@@@@@@@@@@@@@@@@@@@@@@@@@@@               -%%+                                  ");
        printf("%s\n", "@@@@@@            .@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                                     ");
        printf("%s\n", "......         :%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%                                                  ");
        printf("%s\n", "               :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                                  ");
        printf("%s\n", "               :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                                  ");
        printf("%s\n", "               :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                                  ");
        printf("%s\n", "               :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                                  ");
        printf("%s\n", "            ...-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@....                                              ");
        printf("%s\n", "            *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                              ");
        printf("%s\n", "            *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                              ");
        printf("%s\n", "            *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                                              ");
        printf("%s\n", "                                                                                                    ");
        printf("%s\n", "                                                                                                    ");
    }
}

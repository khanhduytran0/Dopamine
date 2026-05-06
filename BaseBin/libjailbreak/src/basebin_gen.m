#import "libjailbreak.h"
#import "carboncopy.h"
#import "codesign.h"
#import <Foundation/Foundation.h>
#import <sys/sysctl.h>

int apply_dyld_patch(NSString *dyldPath, const char *newUUIDPrefix)
{
	MachO *dyldMacho = macho_init_for_writing(dyldPath.fileSystemRepresentation);
	if (!dyldMacho) return -1;

	__block int r = 0;

	// Make AMFI flags always be `0xff`, allows DYLD_* variables to always work
	__block uint64_t getAMFIAddr = 0;
    __block uint64_t platformLoadableAddr = 0;
    __block uint64_t dyldCacheOverridableAddr = 0;
    __block uint64_t dyldCacheAlwaysOverridableAddr = 0;
    char *platformLoadableSym = NULL;
        
    if (__builtin_available(iOS 18.4, *)) {
        platformLoadableSym = "__ZNK6mach_o6Header19loadableIntoProcessENS_8PlatformE7CStringb";
    } else {
        platformLoadableSym = "__ZNK5dyld39MachOFile19loadableIntoProcessENS_8PlatformEPKcb";
    }
    
    macho_enumerate_symbols(dyldMacho, ^(const char *name, uint8_t type, uint64_t vmaddr, bool *stop){
        if (!strcmp(name, "__ZN5dyld413ProcessConfig8Security7getAMFIERKNS0_7ProcessERNS_15SyscallDelegateE")) {
            getAMFIAddr = vmaddr;
        }
        if (!strcmp(name, platformLoadableSym)) {
            platformLoadableAddr = vmaddr;
        }
        if (!strcmp(name, "__ZNK5dyld413ProcessConfig9DyldCache17isOverridablePathEPKc")) {
            dyldCacheOverridableAddr = vmaddr;
        }
        if (!strcmp(name, "__ZN5dyld413ProcessConfig9DyldCache23isAlwaysOverridablePathEPKc")) {
            dyldCacheAlwaysOverridableAddr = vmaddr;
        }
    });
    
	uint32_t getAMFIPatch[] = {
		0xd2801fe0, // mov x0, 0xff
		0xd65f03c0  // ret
	};
    
    uint32_t return1Patch[] = {
        0xd2800020, // mov x0, #1
        0xd65f03c0  // ret
    };

	if (getAMFIAddr == 0) {
        printf("Error: Failed patchfinding getAMFI\n");
        return -1;
    } else if (platformLoadableAddr == 0) {
        printf("Error: Failed patchfinding platformLoadable\n");
        return -1;
    } else if (dyldCacheOverridableAddr == 0) {
        printf("Error: Failed patchfinding dyldCacheOverridable\n");
        return -1;
    } else if (dyldCacheAlwaysOverridableAddr == 0) {
        printf("Error: Failed patchfinding dyldCacheAlwaysOverridable\n");
        return -1;
    }
    
	macho_write_at_vmaddr(dyldMacho, getAMFIAddr, sizeof(getAMFIPatch), getAMFIPatch);
    macho_write_at_vmaddr(dyldMacho, platformLoadableAddr, sizeof(return1Patch), return1Patch);
    macho_write_at_vmaddr(dyldMacho, dyldCacheOverridableAddr, sizeof(return1Patch), return1Patch);
    macho_write_at_vmaddr(dyldMacho, dyldCacheAlwaysOverridableAddr, sizeof(return1Patch), return1Patch);

	// iOS 16+: Change LC_UUID to prevent the kernel from using the in-cache dyld
	macho_enumerate_load_commands(dyldMacho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
		if (loadCommand.cmd == LC_UUID) {
            // The new UUID will look like this:
            // DOPA<dopamine version>\0<rest of original UUID>
            // This way we ensure:
            // - The version it was patched on and it being patched by Dopamine is identifiable later
            // - The UUID is still unique based on the source dyld that was patched

            size_t newUUIDPrefixLen = strlen(newUUIDPrefix) + 1;
            if (newUUIDPrefixLen <= sizeof(uuid_t)) {
                // Also write null byte here, because otherwise it's impossible to know where the version string ends
                macho_write_at_offset(dyldMacho, offset + offsetof(struct uuid_command, uuid), newUUIDPrefixLen, newUUIDPrefix);
            }
            else {
				r = -1;
                printf("Error: Failed to write identifier to LC_UUID, too long (%zu)\n", newUUIDPrefixLen);
            }
			*stop = true;
		}
	});

	macho_free(dyldMacho);
	return r;
}

NSString *dyldhook_dylib_for_platform(void)
{
	cpu_subtype_t cpusubtype = 0;
	size_t len = sizeof(cpusubtype);
	if (sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0) == -1) { return nil; }
	if ((cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
		if (@available(iOS 16.0, *)) {
			return @"dyldhook_merge.arm64e.dylib"; 
		}
		else {
			return @"dyldhook_merge.arm64e.iOS15.dylib"; 
		}
	}
	else {
		if (@available(iOS 16.0, *)) {
			return @"dyldhook_merge.arm64.dylib"; 
		}
		else {
			return @"dyldhook_merge.arm64.iOS15.dylib"; 
		}
	}
}

int merge_dyldhook(NSString *originalDyldPath, NSString *outPath)
{
	NSString *dyldhookMergeDylibName = dyldhook_dylib_for_platform();
	if (!dyldhookMergeDylibName) {
		printf("Error: Failed to locate dyldhook.dylib\n");
		return -1;
	}

	NSString *dyldhookMergeDylibPath = [JBROOT_PATH(@"/basebin") stringByAppendingPathComponent:dyldhookMergeDylibName];
	int r = exec_cmd(JBROOT_PATH("/basebin/MachOMerger"), originalDyldPath.fileSystemRepresentation, dyldhookMergeDylibPath.fileSystemRepresentation, outPath.fileSystemRepresentation, NULL);
	if (r == 0) {
		r = chmod(outPath.fileSystemRepresentation, 0755);
	}
	return r;
}

int basebin_generate(bool comingFromJBUpdate)
{
	NSString *basebinPath    = JBROOT_PATH(@"/basebin");
	NSString *genPath        = JBROOT_PATH(@"/basebin/gen");
	NSString *fakelibPath    = JBROOT_PATH(@"/basebin/.fakelib");
	NSString *systemhookPath = JBROOT_PATH(@"/basebin/systemhook.dylib");

	[[NSFileManager defaultManager] createDirectoryAtPath:genPath withIntermediateDirectories:YES attributes:nil error:nil];

	NSString *fakelibDyldPath        = [fakelibPath stringByAppendingPathComponent:@"dyld"];
	NSString *fakelibSystemHookPath  = [fakelibPath stringByAppendingPathComponent:@"systemhook.dylib"];

	NSString *dyldOrigPath     = [genPath stringByAppendingPathComponent:@"dyld.orig"];
	NSString *dyldInflightPath = [genPath stringByAppendingPathComponent:@"dyld.inflight"];
	NSString *dyldOldPath      = [genPath stringByAppendingPathComponent:@"dyld.old"];
	NSString *dyldPatchedPath  = [genPath stringByAppendingPathComponent:@"dyld"];

	NSString *dopamineVersion = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.version") encoding:NSUTF8StringEncoding error:nil];
	if (!dopamineVersion) return 1;

	if (!comingFromJBUpdate) {
		// Copy /usr/lib to /var/jb/basebin/.fakelib
		[[NSFileManager defaultManager] removeItemAtPath:fakelibPath error:nil];
		[[NSFileManager defaultManager] createDirectoryAtPath:fakelibPath withIntermediateDirectories:YES attributes:nil error:nil];
		carbonCopy(@"/usr/lib", fakelibPath);

		// Delete the dyld inside .fakelib
		[[NSFileManager defaultManager] removeItemAtPath:fakelibDyldPath error:nil];

		// Symlink .fakelib/dyld -> /var/jb/basebin/gen/dyld
		[[NSFileManager defaultManager] createSymbolicLinkAtPath:fakelibDyldPath withDestinationPath:dyldPatchedPath error:nil];

		// Symlink .fakelib/systemhook.dylib -> /var/jb/basebin/systemhook.dylib
		[[NSFileManager defaultManager] createSymbolicLinkAtPath:fakelibSystemHookPath withDestinationPath:systemhookPath error:nil];

		// Backup original dyld
		carbonCopy(@"/usr/lib/dyld", dyldOrigPath);
	}

	carbonCopy(dyldOrigPath, dyldInflightPath);

	NSString *dyldUUIDPrefix = [@"DOPA" stringByAppendingString:dopamineVersion];
	if (apply_dyld_patch(dyldInflightPath, dyldUUIDPrefix.UTF8String) != 0) return 2;
	if (merge_dyldhook(dyldInflightPath, dyldInflightPath) != 0) return 3;
	if (resign_file(dyldInflightPath, @"com.apple.darwin.ignition", YES) != 0) return 4;

	if (comingFromJBUpdate) {
		// We cannot delete dyld as this point because it's still in use
		// If we did this, we'd panic the system
		// So we will move the past patched dyld to dyld.old to keep the vnode alive
		// If there is another dyld.old at this point, we will remove it now
		// since it is guaranteed to not be in use at this point
		if ([[NSFileManager defaultManager] fileExistsAtPath:dyldOldPath]) {
			[[NSFileManager defaultManager] removeItemAtPath:dyldOldPath error:nil];
		}
		[[NSFileManager defaultManager] moveItemAtPath:dyldPatchedPath toPath:dyldOldPath error:nil];
	}

	[[NSFileManager defaultManager] moveItemAtPath:dyldInflightPath toPath:dyldPatchedPath error:nil];
	return 0;
}

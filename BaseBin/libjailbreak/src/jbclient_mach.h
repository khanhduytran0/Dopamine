#ifndef __JBCLIENT_MACH
#define __JBCLIENT_MACH

#include <mach/mach.h>
#include <stdint.h>
#include "jbserver.h"

mach_port_t jbclient_mach_get_launchd_port(void);
int jbclient_mach_send_msg_internal(mach_msg_header_t *hdr, struct jbserver_mach_msg_reply *reply, mach_port_t launchdPort, mach_port_t replyPort, boolean_t isReceivingPort);
int jbclient_mach_process_checkin(char *jbRootPathOut, char *bootUUIDOut, char *sandboxExtensionsOut, bool *fullyDebuggedOut);
int jbclient_mach_fork_fix(pid_t childPid);
int jbclient_mach_trust_file(int fd, struct siginfo *siginfo);

#endif

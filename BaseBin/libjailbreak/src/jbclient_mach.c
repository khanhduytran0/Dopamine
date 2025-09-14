#include "jbclient_mach.h"
#include <dispatch/dispatch.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <pthread.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
extern int fileport_makeport (int fd, mach_port_t * port);

// https://stackoverflow.com/a/35447525
typedef struct {
    mach_msg_header_t          header;
    mach_msg_body_t            body;
    mach_msg_port_descriptor_t task_port;
} send_port_msg;
void fill_send_port_msg(send_port_msg *msg) {
    if (getppid() == 1) {
        // this is probably launchd_sim
        msg->header.msgh_local_port = MACH_PORT_NULL;
    } else {
        // can't send a null port, as launchd_sim will kill us
        msg->header.msgh_local_port = mig_get_reply_port();
    }
    msg->header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, 0) |
        MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_size = sizeof(*msg);

    msg->body.msgh_descriptor_count = 1;
    msg->task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg->task_port.type = MACH_MSG_PORT_DESCRIPTOR;
}
void send_port(mach_port_t remote_port, mach_port_t port) {
    kern_return_t err;

    send_port_msg msg;
    fill_send_port_msg(&msg);
    msg.header.msgh_remote_port = remote_port;
    msg.header.msgh_id = TANK_SERVER_GET_LAUNCHD_PORT;
    msg.task_port.name = port;
    //err = mach_msg_send(&msg.header);
    err = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size,
                    0, MACH_PORT_NULL,
                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}
mach_port_t recv_port(mach_port_t recv_port) {
    kern_return_t err;
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
        mach_msg_trailer_t         trailer;
    } msg;

    err = mach_msg(&msg.header, MACH_RCV_MSG,
                    0, sizeof msg, recv_port,
                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    //assert(err == KERN_SUCCESS);

    return msg.task_port.name;
}
mach_port_t setup_recv_port(void)
{
    mach_port_t p = MACH_PORT_NULL;
    kern_return_t kr = _kernelrpc_mach_port_allocate_trap(task_self_trap(), MACH_PORT_RIGHT_RECEIVE, &p);
    //assert(kr == KERN_SUCCESS);
    kr = _kernelrpc_mach_port_insert_right_trap(task_self_trap(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    //assert(kr == KERN_SUCCESS);
    return p;
}
mach_port_t launchd_sim_mach_get_bootstrap_port(mach_port_t tank_port)
{
    mach_port_t port = setup_recv_port();
    send_port(tank_port, port);
    mach_port_t bootstrap_port = recv_port(port);
    _kernelrpc_mach_port_deallocate_trap(task_self_trap(), port);
    return bootstrap_port;
}
extern bool gDyldhookInSimulator;
mach_port_t jbclient_mach_get_launchd_port(void)
{
	static mach_port_t launchdPort = MACH_PORT_NULL;
    if(launchdPort == MACH_PORT_NULL) {
        task_get_bootstrap_port(task_self_trap(), &launchdPort);
        // launchdPort might be null if we're in xpcproxy
        if(launchdPort != MACH_PORT_NULL && gDyldhookInSimulator) {
            mach_port_t launchdHostPort = launchd_sim_mach_get_bootstrap_port(launchdPort);
            if(launchdHostPort != MACH_PORT_NULL) {
                launchdPort = launchdHostPort;
            }
        }
    }
	return launchdPort;
}

kern_return_t jbclient_mach_send_msg(mach_msg_header_t *hdr, struct jbserver_mach_msg_reply *reply)
{
	mach_port_t replyPort = mig_get_reply_port();
	if (!replyPort)
		return KERN_FAILURE;
	
	mach_port_t launchdPort = jbclient_mach_get_launchd_port();
	if (!launchdPort)
		return KERN_FAILURE;
	
	hdr->msgh_bits |= MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);

	// size already set
	hdr->msgh_remote_port  = launchdPort;
	hdr->msgh_local_port   = replyPort;
	hdr->msgh_voucher_port = 0;
	hdr->msgh_id           = 0x40000000 | 206;
	// 206: magic value to make WebContent work (seriously, this is the only ID that the WebContent sandbox allows)
	
	kern_return_t kr = mach_msg(hdr, MACH_SEND_MSG, hdr->msgh_size, 0, 0, 0, 0);
	if (kr != KERN_SUCCESS) {
		mach_port_deallocate(task_self_trap(), launchdPort);
		return kr;
	}
	
	kr = mach_msg(&reply->msg.hdr, MACH_RCV_MSG, 0, reply->msg.hdr.msgh_size, replyPort, 0, 0);
	if (kr != KERN_SUCCESS) {
		mach_port_deallocate(task_self_trap(), launchdPort);
		return kr;
	}
	
	// Get rid of any rights we might have received
	mach_msg_destroy(&reply->msg.hdr);
	//mach_port_deallocate(task_self_trap(), launchdPort);
	return KERN_SUCCESS;
}

int jbclient_mach_process_checkin(char *jbRootPathOut, char *bootUUIDOut, char *sandboxExtensionsOut, bool *fullyDebuggedOut)
{
	struct jbserver_mach_msg_checkin msg;
	msg.base.hdr.msgh_size = sizeof(msg);
	msg.base.hdr.msgh_bits = 0;
	msg.base.action = JBSERVER_MACH_CHECKIN;
	msg.base.magic = JBSERVER_MACH_MAGIC;

	size_t replySize = sizeof(struct jbserver_mach_msg_checkin_reply) + MAX_TRAILER_SIZE;
	uint8_t replyU[replySize];
	bzero(replyU, replySize);
	struct jbserver_mach_msg_checkin_reply *reply = (struct jbserver_mach_msg_checkin_reply *)&replyU;
	reply->base.msg.hdr.msgh_size = replySize;

	kern_return_t kr = jbclient_mach_send_msg(&msg.base.hdr, (struct jbserver_mach_msg_reply *)reply);
	if (kr != KERN_SUCCESS) return kr;

	reply->jbRootPath[sizeof(reply->jbRootPath)-1] = '\0';
	if (jbRootPathOut) strcpy(jbRootPathOut, reply->jbRootPath);

	reply->bootUUID[sizeof(reply->bootUUID)-1] = '\0';
	if (bootUUIDOut) strcpy(bootUUIDOut, reply->bootUUID);

	reply->sandboxExtensions[sizeof(reply->sandboxExtensions)-1] = '\0';
	if(sandboxExtensionsOut) strcpy(sandboxExtensionsOut, reply->sandboxExtensions);

	if (fullyDebuggedOut) *fullyDebuggedOut = reply->fullyDebugged;

	return (int)reply->base.status;
}

int jbclient_mach_fork_fix(pid_t childPid)
{
	struct jbserver_mach_msg_forkfix msg;
	msg.base.hdr.msgh_size = sizeof(msg);
	msg.base.hdr.msgh_bits = 0;
	msg.base.action = JBSERVER_MACH_FORK_FIX;
	msg.base.magic = JBSERVER_MACH_MAGIC;

	msg.childPid = childPid;

	size_t replySize = sizeof(struct jbserver_mach_msg_forkfix_reply) + MAX_TRAILER_SIZE;
	uint8_t replyU[replySize];
	bzero(replyU, replySize);
	struct jbserver_mach_msg_forkfix_reply *reply = (struct jbserver_mach_msg_forkfix_reply *)&replyU;
	reply->base.msg.hdr.msgh_size = replySize;

	kern_return_t kr = jbclient_mach_send_msg(&msg.base.hdr, (struct jbserver_mach_msg_reply *)reply);
	if (kr != KERN_SUCCESS) return kr;

	return (int)reply->base.status;
}

int jbclient_mach_trust_file(int fd, struct siginfo *siginfo)
{
	struct jbserver_mach_msg_trust_fd msg;
	msg.base.hdr.msgh_size = sizeof(msg);
	msg.base.hdr.msgh_bits = 0;
	msg.base.action = JBSERVER_MACH_TRUST_FILE;
	msg.base.magic = JBSERVER_MACH_MAGIC;

	msg.fd = fd;
	msg.siginfoPopulated = siginfo ? true : false;
	if (siginfo) {
		memcpy(&msg.siginfo, siginfo, sizeof(struct siginfo));
	}

	size_t replySize = sizeof(struct jbserver_mach_msg_trust_fd_reply) + MAX_TRAILER_SIZE;
	uint8_t replyU[replySize];
	bzero(replyU, replySize);
	struct jbserver_mach_msg_trust_fd_reply *reply = (struct jbserver_mach_msg_trust_fd_reply *)&replyU;
	reply->base.msg.hdr.msgh_size = replySize;

	kern_return_t kr = jbclient_mach_send_msg(&msg.base.hdr, (struct jbserver_mach_msg_reply *)reply);
	if (kr != KERN_SUCCESS) return kr;

	return (int)reply->base.status;
}

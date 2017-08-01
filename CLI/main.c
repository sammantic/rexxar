
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#define NETLINK_CHANNEL 31
#define MAX_PAYLOAD 1024

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct msghdr msg;
struct iovec iov;
int sock_fd;


int main() {

	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_CHANNEL);

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid    = 0;
	dest_addr.nl_groups  = 0;

	/**********************************************************/
	// sending msg
	/**********************************************************/

	nlh  = (struct nlhmsg *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len   = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid   = getpid();
	nlh->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh), "del 192.168.1.3");

	iov.iov_base = (void *)nlh;
	iov.iov_len  = nlh->nlmsg_len;

	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("Sending a message to Raxxer\n");
	sendmsg(sock_fd, &msg, 0);
	printf("Waiting for a message from kernel\n");

	recvmsg(sock_fd, &msg, 0);
	printf("Recevied the message payload: %s\n", NLMSG_DATA(nlh));
	close(sock_fd);
	
	return 0;
	
}

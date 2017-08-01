#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/errno.h>

#define NETLINK_CHANNEL 31

static struct nf_hook_ops netfilter_local;
struct sock *nl_sk = NULL;


static LIST_HEAD(block_list);
struct block_entry {
	struct list_head blist;
	u32 ip;
	char *proto;
	int count;
};
struct block_entry *be, *temp;

void pr_addr(u32 ip)
{
	char address[265];
	sprintf(address,"%u.%u.%u.%u", ((unsigned char *)&ip)[0],\
					     ((unsigned char *)&ip)[1],\
					     ((unsigned char *)&ip)[2],\
					     ((unsigned char *)&ip)[3]);	
	pr_info("address : %s \n", address);
}

unsigned int parse_addr(char *str)
{
	int oct1, oct2, oct3, oct4;

	char arr[4];
	sscanf(str, "%d.%d.%d.%d", &oct1, &oct2, &oct3, &oct4);
	arr[0] = oct1;
	arr[1] = oct2;
	arr[2] = oct3;
	arr[3] = oct4;

	return *(unsigned int *)arr;
}
struct block_entry* insert_ip(struct sk_buff *skb) 
{
	
	if (list_empty(&block_list)) {
		pr_info("Is Empty..\n");
		be = kmalloc(sizeof(struct block_entry), GFP_KERNEL);
		be->ip = ip_hdr(skb)->saddr;
		be->count = 0;
		list_add(&be->blist, &block_list);
		return be;
	} else {
		struct list_head *list;
		struct list_head *tmp;

		list_for_each_safe(list, tmp, &block_list) {
			struct block_entry *tbe = list_entry(list, struct block_entry, blist);
			if( tbe->ip == ip_hdr(skb)->saddr ) {
				return tbe;
			}
		}
	}
}


int remove_ip(u32 saddr)
{
	if (list_empty(&block_list))
		return 0;
	
	struct list_head *list;
	struct list_head *tmp;

	list_for_each_safe(list, tmp, &block_list) {
		struct block_entry *tbe = list_entry(list, struct block_entry, blist);
		pr_addr(tbe->ip);
		if ( tbe->ip == saddr ) {
			pr_info("Ip has been deleted!.");
			tbe->count = 0;
			return 0;
		}
	}
}

unsigned int main_rule (unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okf)(struct sk_buff*))
{
			
	if ( ip_hdr(skb)->protocol == IPPROTO_ICMP) {
		
		temp = insert_ip(skb);				
		
		if (ip_hdr(skb)->saddr == temp->ip) {
			temp->count = temp->count + 1;
			pr_info("Counter : %d \n", temp->count);
			if (temp->count > 5) {
				return NF_DROP;
			} else {
				return NF_ACCEPT;
			}
		}
	} else {
		return NF_ACCEPT;
	}
}

static void command_nl_rcv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg = "Rexxar: consider it done!.";
	char command[255],ip[255];
	int res;

	msg_size = strlen(msg);

	nlh = (struct nlmsghdr *) skb->data;
	
	sscanf((char *)nlmsg_data(nlh), "%s %s",command, ip);
	pr_info("Command : %s , ip : %s",command, ip);
	pr_info("Rexxar: Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
        
	if (strcmp(command, "del") == 0) {
		pr_info("Command excuted..!\n");
		remove_ip(parse_addr(ip));
	}
	
	pid = nlh->nlmsg_pid;

	skb_out = nlmsg_new(msg_size, 0);
	
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlh), msg, msg_size);

	nlmsg_unicast(nl_sk, skb_out, pid);
}

int __init start(void) 
{
	netfilter_local.hook     = (nf_hookfn *) main_rule;
	netfilter_local.pf       = PF_INET;
	netfilter_local.hooknum  = NF_INET_LOCAL_IN;
	netfilter_local.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&netfilter_local);
	
	struct netlink_kernel_cfg cfg = {
		.input = command_nl_rcv_msg,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_CHANNEL, &cfg);

	pr_info("Hello World\n");
	return 0;
}

void __exit end(void)
{
	struct list_head *list;
	struct list_head *tmp;

	list_for_each_safe(list, tmp, &block_list) {
		struct block_entry *be = list_entry(list, struct block_entry, blist);
		list_del(&be->blist);
		pr_info("List counter: %d \n", be->count);
		kfree(be);
	}
	nf_unregister_hook(&netfilter_local);
	netlink_kernel_release(nl_sk);
	pr_info("goodBye \n");
}

module_init(start);
module_exit(end);

MODULE_AUTHOR("Msamman");
MODULE_DESCRIPTION("New firewall");
MODULE_LICENSE("GPL v2");


#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/byteorder/generic.h>

MODULE_LICENSE("GLP");
int WINDOW = 12345;
int TTL = 255;

MODULE_PARAM(WINDOW, "i");
MODULE_PARAM(TTL, "i");

extern int ip_send_check(struct iphdr*);

static struct nf_hook_ops nfho;

unsigned long csum_fold(unsigned int csum)
{
	unsigned long sum = (unsigned long)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (unsigned long)~sum;
}
unsigned long csum_tcpudp_nofold(unsigned long saddr, unsigned long daddr, unsigned short len,
	unsigned short proto, unsigned int sum) {
	__asm__(
		"addl %1, %0	;\n"
		"adcl %2, %0	;\n"
		"adcl %3, %0	;\n"
		"adcl $0, %0	;\n"
		: "=r"(sum)
		: "g"(daddr), "g"(saddr), "g"((ntohs(len) << 16 + proto * 256), "0"(sum));
	return sum;
}

unsigned long csum_tcpudp_magic(unsigned long saddr, unsigned long daddr, unsigned short len,
	unsigned short proto, unsigned int sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}
int __init mod_init() {
	nfho.hook = hook;
	nfho.hooknum = NF_IP_POST_ROUTING;
	nfho.pf = PF)INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
	return 0;
}
void __exit mod_exit() {
	nf_unregister_hook(&nfho);
}
unsigned int hook(unsigned int hooknum, struct sk_buff** sb, const struct net_device* in,
	const struct net_device* out, int(*okfn)(struct sk_buff*)) {
	struct sk_buff* skb = *sb;
	struct iphdr* iph;
	struct tcphdr* tcph;
	int size, doff, csum, tcplen, iplen, optlen, datalen, len;
	unsigned char* option; long* timestamp;
	unsigned int WINDOW = 65535;
	int TTL = 64, DF = 1, LEN = 60;
	unsigned char opcje[] = "\x02\x04\x66\x66" // MSS o dowolnej wartoci
		"\x01" // NOP
		"\x03\x03\x02" // WSO o wartosci 2
		"\x01\x01" // Dwa NOPy
		"\x08\x10\x00\x00\x00\x00\x00\x00\x00\x00"; // Timestamp - musimy aktualizowac za kazdym razem
	if (!skb) return NF_ACCEPT;
	if (!(skb->nh.iph)) return NF_ACCEPT;
	if (!(skb->nh.iph->protocol!= IPPROTO_TCP)) return NF_ACCEPT;
	
	iph = skb->nh.iph;
	len = ntohs(iph->tot_len);
	iplen = iph->ihl * 4;
	tcplen = tcph->doff << 2;
	
	if(tcph->ack || tpc->rts || tpc->psh || tcp->fin || !tcph->syn)
				return NF_ACCEPT;
	
	iph->ttl = TTL;
	iph->frag_off = DF ? htons(0x4000) : 0;
	tcplen = tpch - sizeof(struct tcphdr);
	datalen = len - (iplen + tcplen);

	timestamp = (long*)(opcje + 12);
	*timestamp = htonl(jiffies);
	option = (char*)(tcph + 1);
	optlen = LEN - 40;
	memcpy(option, opcje, optlen);
	tcph->doff = (sizeof(struct tcphdr) + optlen / 4);
	tcplen = tcph->doff << 2;
	iph->tot_len = htons(iplen + tcplen + datalen);
	skb->len = iplen + tcplen + datalen;
	tcph->window = htons(WINDOW);

	iph->id = 0;
	size = ntohs(iph->tot_len) - (iph->ihl * 4);
	doff = tcph->doff << 2;
	skb->csum = 0;
	csum = csum_partial(skb->h.raw + doff, size - doff, 0);
	skb->csum = csum;
	tpch->check = 0;
	tcph->check = csum_tcpudp_magic(
		iph->saddr,
		iph->daddr,
		size,iph->protocol,
		csum_partial(skb->h.raw,doff,skb->csum)
	);
	ip_send_check(iph);
	return NF_ACCEPT;
}
module_init(mod_init);
module_exit(mod_exit);
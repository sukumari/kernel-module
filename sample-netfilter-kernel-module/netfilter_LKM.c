#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Suman Kumari");


static struct nf_hook_ops *nfho = NULL;

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcp_header;
    struct udphdr *udph;
    if (!skb)
        return NF_ACCEPT;
    iph = (struct iphdr *)skb_network_header(skb);
    
    if (!iph) {
        return NF_ACCEPT;
    }

    if (iph->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        unsigned short int sport = ntohs((unsigned short int)tcp_header->source);
        unsigned short int dport = ntohs((unsigned short int)tcp_header->dest);
        printk(KERN_INFO "sport = %d \t dport = %d", sport, dport);
    
    tcp_header = (struct tcphdr *)(skb_transport_header(skb));
    sport = ntohs((unsigned short int)tcp_header->source);
    dport = ntohs((unsigned short int)tcp_header->dest);
    printk(KERN_INFO "outside method --- sport = %d \t dport = %d", sport, dport);
   
    }
 
    unsigned int src_ip = (unsigned int)iph->saddr;
    unsigned int dest_ip = (unsigned int)iph->daddr;
    printk(KERN_INFO "IPS: %pI4 \t to \t %pI4 \n", &src_ip, &dest_ip);


    return NF_ACCEPT;
}

static int __init netfilter_LKM_init(void)
{
    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    
    nfho->hook  = (nf_hookfn*)hfunc;
    nfho->hooknum   = NF_INET_PRE_ROUTING;
    nfho->pf    = PF_INET;
    nfho->priority  = NF_IP_PRI_FIRST;
    
    nf_register_net_hook(&init_net, nfho);
    printk(KERN_INFO "netfilter LKM net hook has been successfully resgisterd\n"); 
    return 0;
}

static void __exit netfilter_LKM_exit(void)
{
    nf_unregister_net_hook(&init_net, nfho);
    printk(KERN_INFO "netfilter LKM has been successfully unregistered\n"); 
    kfree(nfho);
}

module_init(netfilter_LKM_init);
module_exit(netfilter_LKM_exit);

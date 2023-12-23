#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>        
#include <linux/device.h>                 
#include <linux/fs.h>            
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <net/netfilter/nf_conntrack_helper.h>


#define  DEVICE_NAME "wgfilter"  
#define  CLASS_NAME  "wg"

#define MAX_NODES 10
#define IP_MAX_LENGTH 50
#define MAX_MSG_LEN 100000

static int    majorNumber;                  
static char   message[256] = {0};           
static short  size_of_message;              
static int    numberOpens = 0;              
static struct class*  wgfilterClass  = NULL; 
static struct device* wgfilterDevice = NULL; 

static struct nf_hook_ops *nfho = NULL;

static int num_of_nodes = 0;

static int display_nodes = 0;

static int my_open(struct inode *, struct file *);
static int my_release(struct inode *, struct file *);
static ssize_t my_read(struct file *, char *, size_t, loff_t *);
static ssize_t my_write(struct file *, const char *, size_t, loff_t *);
 
static struct file_operations fops =
{
    .open = my_open,
    .read = my_read,
    .write = my_write,
    .release = my_release,
};

struct packet_data {
    char type_of_packet[10];
    unsigned short int sport;
    unsigned short int dport;
    char src_ip[IP_MAX_LENGTH];
    char dest_ip[IP_MAX_LENGTH];
};

struct ip_packet_info {
    struct list_head next;
    struct packet_data p_data;  
};

struct user_input {
    int display_nodes;
    unsigned int port;
    char ip[50];
};

static struct user_input *u_input = NULL;
static struct packet_data data_to_send;
static unsigned int packet_count;
static char msg[MAX_MSG_LEN] = {0};

static LIST_HEAD(pinfo_head);

static void shallow_copy(struct packet_data *dest_data , struct packet_data *src_data) {
    strcpy(dest_data->type_of_packet, src_data->type_of_packet);
    //dest_data->type_of_packet = src_data->type_of_packet;
    
    dest_data->sport = src_data->sport;
    dest_data->dport = src_data->dport;

    strcpy(dest_data->src_ip, src_data->src_ip);
    strcpy(dest_data->dest_ip, src_data->dest_ip);
    //dest_data->src_ip = src_data->src_ip;
    //dest_data->dest_ip = src_data->dest_ip;
}

static int add_packet_info_node(struct packet_data pd) {
    struct ip_packet_info *tmp_node = NULL;
    ++num_of_nodes;

    if (num_of_nodes > MAX_NODES) {
        struct ip_packet_info *last_node = list_last_entry(&pinfo_head, struct ip_packet_info, next);

        list_del(&last_node->next);

        kfree(last_node);
    }

    tmp_node = kmalloc(sizeof(struct ip_packet_info), GFP_KERNEL);

    if (tmp_node != NULL) {
        shallow_copy(&tmp_node->p_data, &pd);

        INIT_LIST_HEAD(&tmp_node->next);

        list_add(&tmp_node->next, &pinfo_head);

        return 0;
    }

    return -ENOMEM;
}

static void print_packet_info(void) {
    struct ip_packet_info *cursor, *tmp;
    //printk(KERN_INFO "The packet data is \n");

    list_for_each_entry_safe(cursor, tmp, &pinfo_head, next) {
        struct ip_packet_info *next_node = list_next_entry_circular(cursor, &pinfo_head, next);

        printk(KERN_INFO "%5s %10d %10d %10s %10s",
                                    next_node->p_data.type_of_packet,
                                    next_node->p_data.sport,
                                    next_node->p_data.dport,
                                    &next_node->p_data.src_ip,
                                    &next_node->p_data.dest_ip);
    }

    printk(KERN_INFO "\n");
}

static void remove_packet_info_node(void) {
    struct ip_packet_info *cursor, *tmp;
    list_for_each_entry_safe(cursor, tmp, &pinfo_head, next) {
        list_del(&cursor->next);
        kfree(cursor);
    }
    if (list_empty(&pinfo_head)) {
        printk(KERN_INFO "All the elements of list is deleted\n");
    }
}

static int wgchar_init(void){
    printk(KERN_INFO "wgfilter: Initializing the wgfilter LKM\n");
 
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber<0){
        printk(KERN_ALERT "wgfilter failed to register a major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "wgfilter registered correctly with major number %d\n", majorNumber);
 
    wgfilterClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(wgfilterClass)) {               
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(wgfilterClass);         
    }
    
    printk(KERN_INFO "wgfilter device class registered correctly\n");
 
    // Register the device driver
    wgfilterDevice = device_create(wgfilterClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(wgfilterDevice)) {               
        class_destroy(wgfilterClass);          
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(wgfilterDevice);
    }
    printk(KERN_INFO "wgfilter device class created correctly\n"); 
    return 0;
}

static void wgchar_exit(void) {  
    device_destroy(wgfilterClass, MKDEV(majorNumber, 0));    
    class_unregister(wgfilterClass);                         
    class_destroy(wgfilterClass);                            
    unregister_chrdev(majorNumber, DEVICE_NAME);            
    printk(KERN_INFO "wgfilter character devices has been successfully unregistered\n");
}
 
static int my_open(struct inode *inodep, struct file *filep){
    numberOpens++;
    printk(KERN_INFO "wgfilter: Device has been opened %d time(s)\n", numberOpens);
    return 0;
}
 
static ssize_t my_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {

    ssize_t bytes = len < (MAX_MSG_LEN-(*offset)) ? len : MAX_MSG_LEN-(*offset);

    struct ip_packet_info *next_node;
    int pos = 0;

    if (!list_empty(&pinfo_head)) {
        pos += sprintf(msg + pos, "%*s", 10, "Type");
        pos += sprintf(msg + pos, "%*s", 20, "Src Port");
        pos += sprintf(msg + pos, "%*s", 20, "Dest Port");
        pos += sprintf(msg + pos, "%*s", 20, "Src IP");
        pos += sprintf(msg + pos, "%*s", 20, "Dest IP");
        pos += sprintf(msg + pos, "\n");
    }

    rcu_read_lock();

    list_for_each_entry_rcu(next_node, &pinfo_head, next) {
        --(u_input->display_nodes);
        printk("value of node = %d\n", u_input->display_nodes); 
        if (u_input->display_nodes < 0) {
            break;
        }
        pos += sprintf(msg + pos, "%*s", 10, next_node->p_data.type_of_packet);
        pos += sprintf(msg + pos, "%*d", 20, next_node->p_data.sport);
        pos += sprintf(msg + pos, "%*d", 20, next_node->p_data.dport);
        pos += sprintf(msg + pos, "%*s", 20, next_node->p_data.src_ip);
        pos += sprintf(msg + pos, "%*s", 20, next_node->p_data.dest_ip);
        pos += sprintf(msg + pos, "\n");
   
        if (copy_to_user(buffer, msg, bytes)) {
            printk("unable to copy message\n");
            rcu_read_unlock();
            return -EFAULT;
        }

    }
    (*offset) += bytes;

    rcu_read_unlock();

    return bytes;
}

static ssize_t my_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset) {
    //sprintf(message, "%s(%zu letters)", buffer, len);

    copy_from_user(&message, buffer, len);
    u_input = (struct user_input*)kcalloc(1, sizeof(struct user_input), GFP_KERNEL);
    
    sscanf(message, "%d%d%s", &u_input->display_nodes, &u_input->port, u_input->ip);
    printk("user input is %d %d %s\n", u_input->display_nodes, u_input->port, &u_input->ip);
    //size_of_message = strlen(message);
    // printk(KERN_INFO "wgfilter : %d\n", buffer_to_int(message));
    //printk(KERN_INFO "wgfilter: Received %zu characters from the user\n", len);
    return len;
}

static int my_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "wgfilter: Device successfully closed\n");
    return 0;
}

static void process_tcp_packet(struct iphdr *iph, struct tcphdr *tcp_header) {

    snprintf(data_to_send.type_of_packet, 10, "TCP");
    data_to_send.sport = ntohs((unsigned short int)tcp_header->source);
    data_to_send.dport = ntohs((unsigned short int)tcp_header->dest);        
    snprintf(data_to_send.src_ip, IP_MAX_LENGTH, "%pI4",&iph->saddr);
    snprintf(data_to_send.dest_ip, IP_MAX_LENGTH, "%pI4",&iph->daddr);

    add_packet_info_node(data_to_send);

       /* if (data_to_send.sport == u_input->port || data_to_send.dport == u_input->port ) {
            printk(" Dropping packet based on port. The port is either source port or destination port \n");
            //print_packet_info();
            return NF_DROP;
        }

        if (strcmp(data_to_send.dest_ip, u_input->ip) == 0) {
            printk(" Dropping packet based on dest ip \n");
            //print_packet_info();
            return NF_DROP;
        }*/

    print_packet_info();
}

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcp_header;
    struct udphdr *udph;
    if (!skb) {
        return NF_ACCEPT;
    }
    iph = (struct iphdr *)skb_network_header(skb);
    
    if (!iph) {
        return NF_ACCEPT;
    }

    if (iph->protocol == IPPROTO_TCP) {
        //printk("Inside the tcp packet");
        enum ip_conntrack_info ctinfo;
        struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

        if (!ct) {
            printk("ct is empty");
            return NF_ACCEPT;
        }
        
        /*
        tcp_header = tcp_hdr(skb);
        unsigned short int sport = ntohs((unsigned short int)tcp_header->source);
        unsigned short int dport = ntohs((unsigned short int)tcp_header->dest);
        printk(KERN_INFO "sport = %d \t dport = %d", sport, dport);
        */
        
        tcp_header = (struct tcphdr *)(skb_transport_header(skb));
        //printk("Inside the tcp packet data");
        if (tcp_header->syn) {
            printk("received syn packet = %d", ctinfo);
            if (ctinfo == IP_CT_NEW) {
                printk("received new TCP packet");

                process_tcp_packet(iph, tcp_header);

                return NF_ACCEPT;

            } else {
                if (ctinfo == IP_CT_NEW) {

                    return NF_DROP;
                }
            }
        }  
   
        return NF_ACCEPT;        
    } else if (iph->protocol == IPPROTO_ICMP) {
        printk(KERN_INFO "wgfilter : Drop ICMP packet\n");
        //return NF_DROP;
    }
    return NF_ACCEPT;
}

static int __init wg_firewall_init(void)
{
    wgchar_init();
    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    
    nfho->hook  = (nf_hookfn*)hfunc;
    //nfho->hooknum   = NF_INET_PRE_ROUTING;
    nfho->hooknum   = NF_INET_LOCAL_IN;
    //nfho->hooknum   = NF_INET_LOCAL_OUT;
    nfho->pf    = PF_INET;
    nfho->priority  = NF_IP_PRI_CONNTRACK;
    
    nf_register_net_hook(&init_net, nfho);
    printk(KERN_INFO "wg firewall has been successfully resgisterd\n");
    return 0;
}

static void __exit wg_firewall_exit(void)
{
    kfree(u_input);
    remove_packet_info_node();
    wgchar_exit();
    nf_unregister_net_hook(&init_net, nfho);
    printk(KERN_INFO "Goodbye from wg firewall\n\n\n"); 
    kfree(nfho);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Suman Kumari");
MODULE_DESCRIPTION("A firewall using netfilter and character devices");  
MODULE_VERSION("0.1");

module_init(wg_firewall_init);
module_exit(wg_firewall_exit);

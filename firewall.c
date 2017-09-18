#include <linux/module.h> 
#include <linux/kernel.h>  
#include <linux/proc_fs.h>    
#include <linux/list.h> 
#include <asm/uaccess.h> 
#include <linux/udp.h> 
#include <linux/tcp.h> 
#include <linux/skbuff.h> 
#include <linux/ip.h> 
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/in.h> 
#include <linux/icmp.h>


// 192.168.1.0/24 (the inside LAN) 
#define INTERNAL  3232235776 
#define INTERNAL_MASK 24 
 
// 192.168.2.0/24 (the outside WAN) 
#define EXTERNAL 3232236032 
#define EXTERNAL_MASK 24 
 
// webserver - 192.168.1.100 (the web server IP address) 
#define WEBSERVER 3232235876 
 
static struct nf_hook_ops nfho; 

 
/*Converts subnet prefix number to integer subnet mask*/ 
unsigned int prefix_to_subnet_mask(unsigned int prefix){ 
  unsigned int mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF; 
  return (unsigned int) mask; 
} 

/*returns TRUE if target_ip is present in network_ip/subnet_prefix else returns FALSE*/
bool  is_ip_address_in_subnet(unsigned int target_ip, unsigned int network_ip, unsigned int subnet_prefix){ 
 
  unsigned int subnet_mask = prefix_to_subnet_mask(subnet_prefix); 
 
  unsigned int netstart = (network_ip & subnet_mask); // first ip in subnet 
  unsigned int netend = (netstart | ~subnet_mask); // last ip in subnet 
 
 
  if ((target_ip >= netstart) && (target_ip <= netend)) 
    {return 1==1;} 
  
  return 0==1; 
 
}

/*main_hook_function*/
unsigned int main_hook_func(unsigned int hooknum, struct sk_buff *skb,  
			    const struct net_device *in, const struct net_device *out, 
			    int (*okfn)(struct sk_buff *)) { 
  
  /*Structures for fetching information in IP_header, ICMP_Header and TCP_Header */ 
  struct iphdr *ip_header = (struct iphdr *)ip_hdr(skb);
  struct icmphdr *icmp_header; 
  struct tcphdr *tcp_header; 
  
  /*Variables for fetching particular information from header Structure*/ 
  unsigned int src_ip = (unsigned int)ip_header->saddr; 
  unsigned int dest_ip = (unsigned int)ip_header->daddr; 
  unsigned int icmp_type = 0; 
  unsigned int src_port = 0; 
  unsigned int dest_port = 0; 
  
  /*ICMP packet protocol = 1...fetch required information*/
  if (ip_hdr(skb)->protocol == 1) { 
    icmp_header = (struct icmphdr *)icmp_hdr(skb); 
    icmp_type = icmp_hdr(skb)->type; 
  }
  /*TCP packet protocol = 6.....fetch required information*/
  else if (ip_hdr(skb)->protocol == 6) { 
    tcp_header = (struct tcphdr *)(tcp_hdr(skb)); 
    src_port = ntohs(tcp_hdr(skb)->source);
    dest_port = ntohs(tcp_hdr(skb)->dest); 
  } 
        
  char * eth0 = "eth0"; 
  /*
  No debugging for packets that arrive on the management interface(eth0) of geni nodes.
  */
  if(!((strcmp(in->name,eth0)) == 0)){ 
    printk(KERN_INFO "DEBUG Packet: interface: %s, " 
	   "source ip: (%pI4), " 
	   "destination ip: (%pI4); source port: %u , " 
	   "dest port: %u; protocol: %u\n", 
	   in->name, &src_ip, &dest_ip,src_port,  
	   dest_port,  
	   ip_header->protocol);}  
  /*
  Firewall allows all packets that belong to management interface.
  */  
  if(((strcmp(in->name,eth0)) == 0)) 
    return NF_ACCEPT; 
  /*
  Firewall allows all packets that are destined to external network.
  */
  if(is_ip_address_in_subnet(ntohl(dest_ip),EXTERNAL,EXTERNAL_MASK)){
    return NF_ACCEPT;
  }

  //Firewall Rule # 1
  if (ip_hdr(skb)->protocol == 1){ 
    if(is_ip_address_in_subnet(ntohl(src_ip),EXTERNAL,EXTERNAL_MASK)) { 
      if(icmp_hdr(skb)->type == 8){ 
	if(!is_ip_address_in_subnet(ntohl(dest_ip),WEBSERVER,32)){                   
	  printk(KERN_INFO "RULE 1: BLOCKED ICMP ECHO REQUEST from EXTERNAL host (%pI4) on %s " 
		 "to INTERNAL HOST%pI4.",  
		 &src_ip, in->name, &dest_ip); 
	  printk(KERN_INFO "ECHO_REQUEST %d",icmp_hdr(skb)->type); 
	  return NF_DROP; 
	} 
      } 
    }  
    return NF_ACCEPT; 
  }  
 
  // Firewall Rule # 2 
  if (ip_header->protocol == IPPROTO_TCP && ntohs(tcp_hdr(skb)->dest) == 22) { 
    printk(KERN_INFO "SSH PACKET DROP\n");        
    if(is_ip_address_in_subnet(ntohl(src_ip),EXTERNAL,EXTERNAL_MASK)){ 
      printk(KERN_INFO "Rule 2:BLOCKED SSH connection from an EXTERNAL host (%pI4) on %s " 
	     "on tcp port 22 of %pI4.",  
	     &src_ip, in->name, &dest_ip); 
      return NF_DROP; 
    } 
  } 
 
  //Firewall Rule # 3  
  if ( ntohs(tcp_hdr(skb)->dest) == 80) { 
    if(is_ip_address_in_subnet(ntohl(src_ip),EXTERNAL,EXTERNAL_MASK)){ 
      if (!is_ip_address_in_subnet(ntohl(dest_ip),WEBSERVER,32)){
	printk(KERN_INFO "Rule 3: BLOCKED HTTP connection from an EXTERNAL host (%pI4) on %s " 
	       "to an internal host %pI4 " 
	       " on tcp port 80.",  
	       &src_ip, in->name, &dest_ip); 
	return NF_DROP; 
      }  
    }return NF_ACCEPT; 
  }
  return NF_ACCEPT; 
}

//Function for initilization of module  
int init_module() {
  nfho.hook = main_hook_func; 
  nfho.hooknum = NF_INET_PRE_ROUTING; 
  nfho.pf = PF_INET; 
  nfho.priority = NF_IP_PRI_FIRST; 

  /* Register the hook with the NetFilter API. */ 
  nf_register_hook(&nfho); 
  printk(KERN_INFO "Firewall kernel module loaded.\n"); 
  return 0; 
} 
  
/*Function for cleanup of module*/ 
void cleanup_module() {
  nf_unregister_hook(&nfho); 
  printk(KERN_INFO "Firewall kernel module unloaded.\n"); 
} 

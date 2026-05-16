#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/icmp.h>

static struct nf_hook_ops hook2;
static struct nf_hook_ops block_telnet;
static struct nf_hook_ops block_ping;
// aapostol 16.05.2026
static struct nf_hook_ops pre_routing, local_in, forward, local_out, post_routing;

unsigned int blockTelnet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcphdr;

  u16 port = 23;

  if (!skb)
    return NF_ACCEPT;
  iph = ip_hdr(skb);
  if (iph->protocol == IPPROTO_TCP)
  {
    tcphdr = tcp_hdr(skb);
    if (ntohs(tcphdr->dest) == 23)
    {
      printk(KERN_WARNING "*** Dropping telnet (TCP), port %d\n", &(iph->daddr), port);
      return NF_DROP;
    }
  }
  return NF_ACCEPT;
}

unsigned int blockPing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct icmphdr *icmph;

  if (!skb)
    return NF_ACCEPT;

  iph = ip_hdr(skb);
  if (iph->protocol == IPPROTO_ICMP)
  {
    icmph = icmp_hdr(skb);
    if (icmph->type == ICMP_ECHO)
    {
      printk(KERN_WARNING "*** Dropping ping (ICMP ECHO) from %pI4\n", &(iph->saddr));
      return NF_DROP;
    }
  }
  return NF_ACCEPT;
}


unsigned int blockUDP(void *priv, struct sk_buff *skb,
                      const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct udphdr *udph;

  u16 port = 53;
  char ip[16] = "8.8.8.8";
  u32 ip_addr;

  if (!skb)
    return NF_ACCEPT;

  iph = ip_hdr(skb);
  // Convert the IPv4 address from dotted decimal to 32-bit binary
  in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

  if (iph->protocol == IPPROTO_UDP)
  {
    udph = udp_hdr(skb);
    if (iph->daddr == ip_addr && ntohs(udph->dest) == port)
    {
      printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), port);
      return NF_DROP;
    }
  }
  return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
  struct iphdr *iph;
  char *hook;
  char *protocol;

  switch (state->hook)
  {
  case NF_INET_LOCAL_IN:
    hook = "LOCAL_IN";
    break;
  case NF_INET_LOCAL_OUT:
    hook = "LOCAL_OUT";
    break;
  case NF_INET_PRE_ROUTING:
    hook = "PRE_ROUTING";
    break;
  case NF_INET_POST_ROUTING:
    hook = "POST_ROUTING";
    break;
  case NF_INET_FORWARD:
    hook = "FORWARD";
    break;
  default:
    hook = "IMPOSSIBLE";
    break;
  }
  printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

  iph = ip_hdr(skb);
  switch (iph->protocol)
  {
  case IPPROTO_UDP:
    protocol = "UDP";
    break;
  case IPPROTO_TCP:
    protocol = "TCP";
    break;
  case IPPROTO_ICMP:
    protocol = "ICMP";
    break;
  default:
    protocol = "OTHER";
    break;
  }
  // Print out the IP addresses and protocol
  printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n",
         &(iph->saddr), &(iph->daddr), protocol);

  return NF_ACCEPT;
}

int registerFilter(void)
{
  printk(KERN_INFO "Registering filters.\n");
  hook2.hook = blockUDP;
  hook2.hooknum = NF_INET_POST_ROUTING;
  hook2.pf = PF_INET;
  hook2.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &hook2);

  // aapostol

  // ping filter (block incoming ICMP echo requests to this host)
  block_ping.hook = blockPing;
  block_ping.hooknum = NF_INET_LOCAL_IN;
  block_ping.pf = PF_INET;
  block_ping.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &block_ping);

  // telnet filter
  block_telnet.hook = blockTelnet;
  block_telnet.hooknum = NF_INET_LOCAL_IN;
  block_telnet.pf = PF_INET;
  block_telnet.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &block_telnet);

  // static struct nf_hook_ops pre_routing, local_in, forward, local_out, post_routing;
  // register printInfo function to all of the netfilter hooks
  pre_routing.hook = printInfo;
  pre_routing.hooknum = NF_INET_PRE_ROUTING;
  pre_routing.pf = PF_INET;
  pre_routing.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &pre_routing);

  local_in.hook = printInfo;
  local_in.hooknum = NF_INET_LOCAL_IN;
  local_in.pf = PF_INET;
  local_in.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &local_in);

  forward.hook = printInfo;
  forward.hooknum = NF_INET_FORWARD;
  forward.pf = PF_INET;
  forward.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &forward);

  local_out.hook = printInfo;
  local_out.hooknum = NF_INET_LOCAL_OUT;
  local_out.pf = PF_INET;
  local_out.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &local_out);

  post_routing.hook = printInfo;
  post_routing.hooknum = NF_INET_POST_ROUTING;
  post_routing.pf = PF_INET;
  post_routing.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &post_routing);
  return 0;
}

void removeFilter(void)
{
  printk(KERN_INFO "The filters are being removed.\n");
  nf_unregister_net_hook(&init_net, &hook2);

  // aapostol
  nf_unregister_net_hook(&init_net, &block_ping);
  nf_unregister_net_hook(&init_net, &block_telnet);

  nf_unregister_net_hook(&init_net, &pre_routing);
  nf_unregister_net_hook(&init_net, &local_in);
  nf_unregister_net_hook(&init_net, &forward);
  nf_unregister_net_hook(&init_net, &local_out);
  nf_unregister_net_hook(&init_net, &post_routing);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");

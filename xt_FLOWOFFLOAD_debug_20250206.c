/*
 * Copyright (C) 2018-2021 Felix Fietkau <nbd@nbd.name>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_FLOWOFFLOAD.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_flow_table.h>

#ifdef CONFIG_OVS_SKIP_ACCEL_ACTION
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <net/gre.h>
#include <net/netfilter/nf_conntrack_acct.h>

static u8 xt_flowoff_debug = 0;
static u8 xt_flowoff_enable = 0;
static u8 xt_flowoff_mark_drop = 3;
static u8 xt_flowoff_mark_inspect = 1;
static u32 xt_flowoff_deferral = 10;

#define DSCP_MAPPING_LEN	8
struct xt_flowoff_dscp_entry {
	u32	mark;
	u32 dscp;
};
struct xt_flowoff_dscp_entry dscp_mapping[DSCP_MAPPING_LEN] = { {10, 0}, {20, 32}, {30, 128}, {40, 192}, {0,0}, {0,0}, {0,0}, {0,0} };
#endif

struct xt_flowoffload_hook {
	struct hlist_node list;
	struct nf_hook_ops ops;
	struct net *net;
	bool registered;
	bool used;
};

struct xt_flowoffload_table {
	struct nf_flowtable ft;
	struct hlist_head hooks;
	struct delayed_work work;
};

struct nf_forward_info {
	const struct net_device *indev;
	const struct net_device *outdev;
	const struct net_device *hw_outdev;
	struct id {
		__u16	id;
		__be16	proto;
	} encap[NF_FLOW_TABLE_ENCAP_MAX];
	u8 num_encaps;
	u8 ingress_vlans;
	u8 h_source[ETH_ALEN];
	u8 h_dest[ETH_ALEN];
	enum flow_offload_xmit_type xmit_type;
};

enum LogLevel {
	Log_err,
	Log_warn,
	Log_debug,
	Log_trace
};

#ifdef CONFIG_OVS_SKIP_ACCEL_ACTION
	static void
xt_LOG(int level, const char *format, ...)
{
	if (level < 0 || level > xt_flowoff_debug)
		return; 

	va_list args;
	va_start(args, format);
	vprintk(format, args);
	va_end(args);
}
#else
	static void
xt_LOG(int level, const char *format, ...)
{
	return;
}
#endif

static DEFINE_SPINLOCK(hooks_lock);

struct xt_flowoffload_table flowtable[2];

#if 1 // opensync-305
#define MTK_DSCP_QID_START     8
#define MTK_QOS_QID_START      16
#define MTK_QOS_ID_BASE        0x44000000
#define MTK_QOS_ID_MASK        0x0000007f
#define QOS_CLASS_MAJOR        0x00010000

static int
xt_flowoffload_set_hqos(struct sk_buff *skb, struct flow_offload *flow, enum ip_conntrack_dir dir)
{
	u8 tos, prec = 0;
	u8 id, qid_ul, qid_dl, qid_qos;

	if ((skb->mark & 0xFFFF0000) == MTK_QOS_ID_BASE)
		qid_qos = skb->mark & MTK_QOS_ID_MASK;
	else if ((skb->priority & 0xFFFF0000) == QOS_CLASS_MAJOR)
		qid_qos = skb->priority & MTK_QOS_ID_MASK;
	else qid_qos = 0;

	if (qid_qos > 0) {
		id = qid_qos - 1;
		if (dir == IP_CT_DIR_ORIGINAL) {
			qid_ul = id + MTK_QOS_QID_START;
			qid_dl = (id & 1) ? (qid_ul - 1) : (qid_ul + 1);
		} else {
			qid_dl = id + MTK_QOS_QID_START;
			qid_ul = (id & 1) ? (qid_dl - 1) : (qid_dl + 1);
		}
		flow->ct->hwmark = (qid_ul << 16) | qid_dl;

	} else {
		tos = flow->tuplehash[dir].tuple.tos;
		prec = IPTOS_PREC(tos) >> 5;
		flow->ct->hwmark = prec + MTK_DSCP_QID_START;
	}

	return 0;
}
#endif

static int
xt_flowoffload_dscp_init(struct sk_buff *skb, struct flow_offload *flow,
			 enum ip_conntrack_dir dir)
{
	const struct flow_offload_tuple *flow_tuple = &flow->tuplehash[dir].tuple;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	u32 offset = 0;
	u8 tos = 0;

	switch (flow_tuple->l3proto) {
	case NFPROTO_IPV4:
		iph = (struct iphdr *)(skb_network_header(skb) + offset);
		tos = iph->tos;
		break;
	case NFPROTO_IPV6:
		ip6h = (struct ipv6hdr *)(skb_network_header(skb) + offset);
		tos = ipv6_get_dsfield(ip6h);
		break;
	default:
		return -1;
	};

	flow->tuplehash[dir].tuple.tos = tos;
	flow->tuplehash[!dir].tuple.tos = tos;

#ifdef CONFIG_OVS_SKIP_ACCEL_ACTION
	if(tos == 0)
	{
		int dscp_idx = 0, dscp = 0;
		struct nf_conn *ct;
		enum ip_conntrack_info ctinfo;

		ct = nf_ct_get(skb, &ctinfo);
		if (ct)
		{
			if(ct->tuplehash[dir].tuple.tos != 0 || ct->tuplehash[!dir].tuple.tos != 0)
			{
				if(ct->tuplehash[dir].tuple.tos != 0)
					tos = ct->tuplehash[dir].tuple.tos;
				else if (ct->tuplehash[!dir].tuple.tos != 0)
					tos = ct->tuplehash[!dir].tuple.tos;

				flow->tuplehash[dir].tuple.tos = flow->tuplehash[!dir].tuple.tos = tos;
			}

			if(tos == 0)
			{
				//
				// changing DSCP by CT mark value.
				// The DSCP value is changed by Openflow rule but it's not working for UDP downstream packets.
				// So we need to decide the DSCP value by CT mark before packets enter fast path.
				//
				for(dscp_idx=0; dscp_idx < DSCP_MAPPING_LEN; dscp_idx++)
				{
					if(ct->mark == dscp_mapping[dscp_idx].mark)
						dscp = dscp_mapping[dscp_idx].dscp;
				}
				
				flow->tuplehash[dir].tuple.tos = flow->tuplehash[!dir].tuple.tos = dscp;
			}
		}
	}
#endif /* CONFIG_OVS_SKIP_ACCEL_ACTION */

	return 0;
}

static unsigned int
xt_flowoffload_net_hook(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct vlan_ethhdr *veth;
	__be16 proto;

	switch (skb->protocol) {
	case htons(ETH_P_8021Q):
		veth = (struct vlan_ethhdr *)skb_mac_header(skb);
		proto = veth->h_vlan_encapsulated_proto;
		break;
	case htons(ETH_P_PPP_SES):
		proto = nf_flow_pppoe_proto(skb);
		break;
	default:
		proto = skb->protocol;
		break;
	}

	switch (proto) {
	case htons(ETH_P_IP):
		return nf_flow_offload_ip_hook(priv, skb, state);
	case htons(ETH_P_IPV6):
		return nf_flow_offload_ipv6_hook(priv, skb, state);
	}

	return NF_ACCEPT;
}

static int
xt_flowoffload_create_hook(struct xt_flowoffload_table *table,
			   struct net_device *dev)
{
	struct xt_flowoffload_hook *hook;
	struct nf_hook_ops *ops;

	hook = kzalloc(sizeof(*hook), GFP_ATOMIC);
	if (!hook)
		return -ENOMEM;

	ops = &hook->ops;
	ops->pf = NFPROTO_NETDEV;
	ops->hooknum = NF_NETDEV_INGRESS;
	ops->priority = 10;
	ops->priv = &table->ft;
	ops->hook = xt_flowoffload_net_hook;
	ops->dev = dev;

	hlist_add_head(&hook->list, &table->hooks);
	mod_delayed_work(system_power_efficient_wq, &table->work, 0);

	return 0;
}

static struct xt_flowoffload_hook *
flow_offload_lookup_hook(struct xt_flowoffload_table *table,
			 struct net_device *dev)
{
	struct xt_flowoffload_hook *hook;

	hlist_for_each_entry(hook, &table->hooks, list) {
		if (hook->ops.dev == dev)
			return hook;
	}

	return NULL;
}

static void
xt_flowoffload_check_device(struct xt_flowoffload_table *table,
			    struct net_device *dev)
{
	struct xt_flowoffload_hook *hook;

	if (!dev)
		return;

	spin_lock_bh(&hooks_lock);
	hook = flow_offload_lookup_hook(table, dev);
	if (hook)
		hook->used = true;
	else
		xt_flowoffload_create_hook(table, dev);
	spin_unlock_bh(&hooks_lock);
}

static void
xt_flowoffload_register_hooks(struct xt_flowoffload_table *table)
{
	struct xt_flowoffload_hook *hook;

restart:
	hlist_for_each_entry(hook, &table->hooks, list) {
		if (hook->registered)
			continue;

		hook->registered = true;
		hook->net = dev_net(hook->ops.dev);
		spin_unlock_bh(&hooks_lock);
		nf_register_net_hook(hook->net, &hook->ops);
		if (table->ft.flags & NF_FLOWTABLE_HW_OFFLOAD)
			table->ft.type->setup(&table->ft, hook->ops.dev,
					      FLOW_BLOCK_BIND);
		spin_lock_bh(&hooks_lock);
		goto restart;
	}

}

static bool
xt_flowoffload_cleanup_hooks(struct xt_flowoffload_table *table)
{
	struct xt_flowoffload_hook *hook;
	bool active = false;

restart:
	spin_lock_bh(&hooks_lock);
	hlist_for_each_entry(hook, &table->hooks, list) {
		if (hook->used || !hook->registered) {
			active = true;
			continue;
		}

		hlist_del(&hook->list);
		spin_unlock_bh(&hooks_lock);
		if (table->ft.flags & NF_FLOWTABLE_HW_OFFLOAD)
			table->ft.type->setup(&table->ft, hook->ops.dev,
					      FLOW_BLOCK_UNBIND);
		nf_unregister_net_hook(hook->net, &hook->ops);
		kfree(hook);
		goto restart;
	}
	spin_unlock_bh(&hooks_lock);

	return active;
}

static void
xt_flowoffload_check_hook(struct flow_offload *flow, void *data)
{
	struct xt_flowoffload_table *table = data;
	struct flow_offload_tuple *tuple0 = &flow->tuplehash[0].tuple;
	struct flow_offload_tuple *tuple1 = &flow->tuplehash[1].tuple;
	struct xt_flowoffload_hook *hook;

	spin_lock_bh(&hooks_lock);
	hlist_for_each_entry(hook, &table->hooks, list) {
		if (hook->ops.dev->ifindex != tuple0->iifidx &&
		    hook->ops.dev->ifindex != tuple1->iifidx)
			continue;

		hook->used = true;
		xt_LOG(Log_debug, "xt_flowoffload: used ingress hook - %s\n", hook->ops.dev->name);
	}
	spin_unlock_bh(&hooks_lock);
}

static void
xt_flowoffload_hook_work(struct work_struct *work)
{
	struct xt_flowoffload_table *table;
	struct xt_flowoffload_hook *hook;
	int err;

	table = container_of(work, struct xt_flowoffload_table, work.work);

	spin_lock_bh(&hooks_lock);
	xt_flowoffload_register_hooks(table);
	hlist_for_each_entry(hook, &table->hooks, list)
		hook->used = false;
	spin_unlock_bh(&hooks_lock);

	err = nf_flow_table_iterate(&table->ft, xt_flowoffload_check_hook,
				    table);
	if (err && err != -EAGAIN)
		goto out;

#ifdef CONFIG_OVS_SKIP_ACCEL_ACTION
	// Back to native behavior for factory mode.
	if(!xt_flowoff_enable)
#endif
	{
		if (!xt_flowoffload_cleanup_hooks(table))
			return;
	}

out:
	queue_delayed_work(system_power_efficient_wq, &table->work, HZ);
}

static bool
xt_flowoffload_skip(struct sk_buff *skb, int family)
{
	if (skb_sec_path(skb))
		return true;

	if (family == NFPROTO_IPV4) {
		const struct ip_options *opt = &(IPCB(skb)->opt);

		if (unlikely(opt->optlen))
			return true;
	}

	return false;
}

static enum flow_offload_xmit_type nf_xmit_type(struct dst_entry *dst)
{
	if (dst_xfrm(dst))
		return FLOW_OFFLOAD_XMIT_XFRM;

	return FLOW_OFFLOAD_XMIT_NEIGH;
}

static void nf_default_forward_path(struct nf_flow_route *route,
				    struct dst_entry *dst_cache,
				    enum ip_conntrack_dir dir,
				    struct net_device **dev)
{
	route->tuple[!dir].in.ifindex	= dst_cache->dev->ifindex;
	route->tuple[dir].dst		= dst_cache;
	route->tuple[dir].xmit_type	= nf_xmit_type(dst_cache);
}

static bool nf_is_valid_ether_device(const struct net_device *dev)
{
	if (!dev){
		xt_LOG(Log_err, "%s : dev value NULL\n", __func__);
		return false; 
	}

	if (!is_valid_ether_addr(dev->dev_addr)){
		xt_LOG(Log_err, "%s : is_valid_ether_addr return 0\n", __func__);
		return false;
	}

	if ((dev->flags & IFF_LOOPBACK) || dev->type != ARPHRD_ETHER ||
	    dev->addr_len != ETH_ALEN){
		xt_LOG(Log_err, "%s : dev->flags : %d / dev->type : %d / dev->addr_len : %d \n", 
				__func__, dev->flags, dev->type, dev->addr_len);
		return false;
	}

	return true;
}

static void nf_dev_path_info(const struct net_device_path_stack *stack,
			     struct nf_forward_info *info,
			     unsigned char *ha)
{
	const struct net_device_path *path;
	int i;

	memcpy(info->h_dest, ha, ETH_ALEN);

	for (i = 0; i < stack->num_paths; i++) {
		path = &stack->path[i];

		info->indev = path->dev;

		switch (path->type) {
		case DEV_PATH_ETHERNET:
		case DEV_PATH_DSA:
		case DEV_PATH_VLAN:
		case DEV_PATH_PPPOE:
			if (is_zero_ether_addr(info->h_source))
				memcpy(info->h_source, path->dev->dev_addr, ETH_ALEN);

			if (path->type == DEV_PATH_ETHERNET)
				break;
			if (path->type == DEV_PATH_DSA) {
				i = stack->num_paths;
				break;
			}

			/* DEV_PATH_VLAN and DEV_PATH_PPPOE */
			if (info->num_encaps >= NF_FLOW_TABLE_ENCAP_MAX) {
				info->indev = NULL;
				break;
			}
			if (!info->outdev)
				info->outdev = path->dev;
			info->encap[info->num_encaps].id = path->encap.id;
			info->encap[info->num_encaps].proto = path->encap.proto;
			info->num_encaps++;
			if (path->type == DEV_PATH_PPPOE)
				memcpy(info->h_dest, path->encap.h_dest, ETH_ALEN);
			break;
		case DEV_PATH_BRIDGE:
			if (is_zero_ether_addr(info->h_source))
				memcpy(info->h_source, path->dev->dev_addr, ETH_ALEN);

			switch (path->bridge.vlan_mode) {
			case DEV_PATH_BR_VLAN_UNTAG_HW:
				info->ingress_vlans |= BIT(info->num_encaps - 1);
				break;
			case DEV_PATH_BR_VLAN_TAG:
				info->encap[info->num_encaps].id = path->bridge.vlan_id;
				info->encap[info->num_encaps].proto = path->bridge.vlan_proto;
				info->num_encaps++;
				break;
			case DEV_PATH_BR_VLAN_UNTAG:
				info->num_encaps--;
				break;
			case DEV_PATH_BR_VLAN_KEEP:
				break;
			}
			break;
		default:
			break;
		}
	}
	if (!info->outdev)
		info->outdev = info->indev;

	info->hw_outdev = info->indev;

	if (nf_is_valid_ether_device(info->indev))
		info->xmit_type = FLOW_OFFLOAD_XMIT_DIRECT;
}

static int nf_dev_fill_forward_path(const struct nf_flow_route *route,
				     const struct dst_entry *dst_cache,
				     const struct nf_conn *ct,
				     enum ip_conntrack_dir dir, u8 *ha,
				     struct net_device_path_stack *stack)
{
	const void *daddr = &ct->tuplehash[!dir].tuple.src.u3;
	struct net_device *dev = dst_cache->dev;
	struct neighbour *n;
	u8 nud_state;

	if (!nf_is_valid_ether_device(dev))
		goto out;

	if (ct->status & IPS_NAT_MASK) {
		n = dst_neigh_lookup(dst_cache, daddr);
		if (!n)
			return -1;

		read_lock_bh(&n->lock);
		nud_state = n->nud_state;
		ether_addr_copy(ha, n->ha);
		read_unlock_bh(&n->lock);
		neigh_release(n);

		if (!(nud_state & NUD_VALID))
			return -1;
	}

out:
	return dev_fill_forward_path(dev, ha, stack);
}

#ifdef CONFIG_OVS_SKIP_ACCEL_ACTION
static struct net_device_path *dev_fwd_path(struct net_device_path_stack *stack)
{
	int k = stack->num_paths++;

	if (WARN_ON_ONCE(k >= NET_DEVICE_PATH_STACK_MAX))
		return NULL;

	return &stack->path[k];
}

// dev_fill_forward_path() copy function
static int dev_fill_forward_path_for_ovs_l2(const struct net_device *dev, const u8 *daddr,
			  struct net_device_path_stack *stack, const struct net_device *real_dev)
{
	const struct net_device *last_dev;
	struct net_device_path_ctx ctx = {
		.dev	= dev,
	};
	struct net_device_path *path;
	int ret = 0;

	memcpy(ctx.daddr, daddr, sizeof(ctx.daddr));
	stack->num_paths = 0;
#if 1   // plume add
	// fill bridge by ourself for ovs bridge traffic accel
	path = dev_fwd_path(stack);
	if (!path){
		xt_LOG(Log_err, "%s/%d : dev_fwd_path is NULL !!!\n", __func__, __LINE__);
		return -1;
	}

	memset(path, 0, sizeof(struct net_device_path));
	path->type = DEV_PATH_BRIDGE;
	path->dev = ctx.dev;
	ctx.dev = real_dev;
#endif // plume add
	while (ctx.dev && ctx.dev->netdev_ops->ndo_fill_forward_path) {
		last_dev = ctx.dev;
		path = dev_fwd_path(stack);
		
		if (!path){
			xt_LOG(Log_err, "%s/%d : dev_fwd_path is NULL !!!\n", __func__, __LINE__);
			return -1;
		}

		memset(path, 0, sizeof(struct net_device_path));
		ret = ctx.dev->netdev_ops->ndo_fill_forward_path(&ctx, path);
		if (ret < 0)
			return -1;

		//if (WARN_ON_ONCE(last_dev == ctx.dev))
		//	return -1;
	}

	if (!ctx.dev)
		return ret;

	path = dev_fwd_path(stack);
	if (!path){
		xt_LOG(Log_err, "%s : dev_fwd_path is NULL !!!\n", __func__);
		return -1;
	}
#if 1
        path->type = DEV_PATH_BRIDGE;
        path->dev = ctx.dev;
#else
	path->type = DEV_PATH_ETHERNET;
	path->dev = ctx.dev;
#endif 

	return ret;
}
#endif

static int nf_dev_forward_path(struct sk_buff *skb,
				struct nf_flow_route *route,
				const struct nf_conn *ct,
				enum ip_conntrack_dir dir,
				struct net_device **devs)
{
	const struct dst_entry *dst = route->tuple[dir].dst;
	struct ethhdr *eth;
	enum ip_conntrack_dir skb_dir;
	struct net_device_path_stack stack;
	struct nf_forward_info info = {};
	unsigned char ha[ETH_ALEN];
	int i;


	if (!(ct->status & IPS_NAT_MASK) && skb_mac_header_was_set(skb)) {
		eth = eth_hdr(skb);
		skb_dir = CTINFO2DIR(skb_get_nfct(skb) & NFCT_INFOMASK);

		if (skb_dir != dir) {
			memcpy(ha, eth->h_source, ETH_ALEN);
			memcpy(info.h_source, eth->h_dest, ETH_ALEN);
		} else {
			memcpy(ha, eth->h_dest, ETH_ALEN);
			memcpy(info.h_source, eth->h_source, ETH_ALEN);
		}
	}

	if (nf_dev_fill_forward_path(route, dst, ct, dir, ha, &stack) >= 0)
		nf_dev_path_info(&stack, &info, ha);

	devs[!dir] = (struct net_device *)info.indev;
	if (!info.indev)
		return -1;

	route->tuple[!dir].in.ifindex = info.indev->ifindex;
	for (i = 0; i < info.num_encaps; i++) {
		route->tuple[!dir].in.encap[i].id = info.encap[i].id;
		route->tuple[!dir].in.encap[i].proto = info.encap[i].proto;
	}
	route->tuple[!dir].in.num_encaps = info.num_encaps;
	route->tuple[!dir].in.ingress_vlans = info.ingress_vlans;

	if (info.xmit_type == FLOW_OFFLOAD_XMIT_DIRECT) {
		memcpy(route->tuple[dir].out.h_source, info.h_source, ETH_ALEN);
		memcpy(route->tuple[dir].out.h_dest, info.h_dest, ETH_ALEN);
		route->tuple[dir].out.ifindex = info.outdev->ifindex;
		route->tuple[dir].out.hw_ifindex = info.hw_outdev->ifindex;
		route->tuple[dir].xmit_type = info.xmit_type;
	}

	return 0;
}

static int
xt_flowoffload_route_dir(struct nf_flow_route *route, const struct nf_conn *ct,
			 enum ip_conntrack_dir dir,
			 const struct xt_action_param *par, int ifindex,
			 struct net_device **devs)
{
	struct dst_entry *dst = NULL;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	switch (xt_family(par)) {
	case NFPROTO_IPV4:
		fl.u.ip4.daddr = ct->tuplehash[!dir].tuple.src.u3.ip;
		fl.u.ip4.flowi4_oif = ifindex;
		break;
	case NFPROTO_IPV6:
		fl.u.ip6.saddr = ct->tuplehash[!dir].tuple.dst.u3.in6;
		fl.u.ip6.daddr = ct->tuplehash[!dir].tuple.src.u3.in6;
		fl.u.ip6.flowi6_oif = ifindex;
		break;
	}

	nf_route(xt_net(par), &dst, &fl, false, xt_family(par));
	if (!dst)
		return -ENOENT;

	nf_default_forward_path(route, dst, dir, devs);

	return 0;
}

static int
xt_flowoffload_route_nat(struct sk_buff *skb, const struct nf_conn *ct,
			 const struct xt_action_param *par,
			 struct nf_flow_route *route, enum ip_conntrack_dir dir,
			 struct net_device **devs)
{
	struct dst_entry *this_dst = skb_dst(skb);
	struct dst_entry *other_dst = NULL;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	switch (xt_family(par)) {
	case NFPROTO_IPV4:
		fl.u.ip4.daddr = ct->tuplehash[dir].tuple.src.u3.ip;
		fl.u.ip4.flowi4_oif = xt_in(par)->ifindex;
		break;
	case NFPROTO_IPV6:
		fl.u.ip6.saddr = ct->tuplehash[!dir].tuple.dst.u3.in6;
		fl.u.ip6.daddr = ct->tuplehash[dir].tuple.src.u3.in6;
		fl.u.ip6.flowi6_oif = xt_in(par)->ifindex;
		break;
	}

	nf_route(xt_net(par), &other_dst, &fl, false, xt_family(par));
	if (!other_dst)
		return -ENOENT;

	nf_default_forward_path(route, this_dst, dir, devs);
	nf_default_forward_path(route, other_dst, !dir, devs);

	if (route->tuple[dir].xmit_type	== FLOW_OFFLOAD_XMIT_NEIGH &&
	    route->tuple[!dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH) {
		if (nf_dev_forward_path(skb, route, ct, dir, devs))
			return -1;
		if (nf_dev_forward_path(skb, route, ct, !dir, devs))
			return -1;
	}

	return 0;
}

static int
xt_flowoffload_route_bridge(struct sk_buff *skb, const struct nf_conn *ct,
			    const struct xt_action_param *par,
			    struct nf_flow_route *route, enum ip_conntrack_dir dir,
			    struct net_device **devs)
{
	int ret;

	ret = xt_flowoffload_route_dir(route, ct, dir, par,
				       devs[dir]->ifindex,
				       devs);
	if (ret)
		return ret;

	ret = xt_flowoffload_route_dir(route, ct, !dir, par,
				       devs[!dir]->ifindex,
				       devs);
	if (ret)
		goto err_route_dir1;

	if (route->tuple[dir].xmit_type	== FLOW_OFFLOAD_XMIT_NEIGH &&
	    route->tuple[!dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH) {
		if (nf_dev_forward_path(skb, route, ct, dir, devs) ||
		    nf_dev_forward_path(skb, route, ct, !dir, devs)) {
			ret = -1;
			goto err_route_dir2;
		}
	}

	return 0;

err_route_dir2:
	dst_release(route->tuple[!dir].dst);
err_route_dir1:
	dst_release(route->tuple[dir].dst);
	return ret;
}

static unsigned int
flowoffload_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct xt_flowoffload_table *table;
	const struct xt_flowoffload_target_info *info = par->targinfo;
	struct tcphdr _tcph, *tcph = NULL;
	enum ip_conntrack_info ctinfo;
	enum ip_conntrack_dir dir;
	struct nf_flow_route route = {};
	struct flow_offload *flow = NULL;
	struct net_device *devs[2] = {};
	struct nf_conn *ct;
	struct net *net;

	if (xt_flowoffload_skip(skb, xt_family(par)))
		return XT_CONTINUE;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL)
		return XT_CONTINUE;

	switch (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum) {
	case IPPROTO_TCP:
		if (ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED)
			return XT_CONTINUE;

		tcph = skb_header_pointer(skb, par->thoff,
					  sizeof(_tcph), &_tcph);
		if (unlikely(!tcph || tcph->fin || tcph->rst))
			return XT_CONTINUE;
		break;
	case IPPROTO_UDP:
		break;
	default:
		return XT_CONTINUE;
	}

	if (nf_ct_ext_exist(ct, NF_CT_EXT_HELPER) ||
	    ct->status & IPS_SEQ_ADJUST)
		return XT_CONTINUE;

	if (!nf_ct_is_confirmed(ct))
		return XT_CONTINUE;

	devs[dir] = xt_out(par);
	devs[!dir] = xt_in(par);

	if (!devs[dir] || !devs[!dir])
		return XT_CONTINUE;

	if (test_and_set_bit(IPS_OFFLOAD_BIT, &ct->status))
		return XT_CONTINUE;

	dir = CTINFO2DIR(ctinfo);

	if (ct->status & IPS_NAT_MASK) {
		if (xt_flowoffload_route_nat(skb, ct, par, &route, dir, devs) < 0)
			goto err_flow_route;
	} else {
		if (xt_flowoffload_route_bridge(skb, ct, par, &route, dir, devs) < 0)
			goto err_flow_route;
	}

	flow = flow_offload_alloc(ct);
	if (!flow)
		goto err_flow_alloc;

	if (flow_offload_route_init(flow, &route) < 0)
		goto err_flow_add;

	if (xt_flowoffload_dscp_init(skb, flow, dir) < 0)
		goto err_flow_add;

	if (tcph) {
		ct->proto.tcp.seen[0].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		ct->proto.tcp.seen[1].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	table = &flowtable[!!(info->flags & XT_FLOWOFFLOAD_HW)];

	net = read_pnet(&table->ft.net);
	if (!net)
		write_pnet(&table->ft.net, xt_net(par));

	if (flow_offload_add(&table->ft, flow) < 0)
		goto err_flow_add;

	xt_flowoffload_check_device(table, devs[0]);
	xt_flowoffload_check_device(table, devs[1]);

	if (!(ct->status & IPS_NAT_MASK))
		dst_release(route.tuple[dir].dst);
	dst_release(route.tuple[!dir].dst);

	return XT_CONTINUE;

err_flow_add:
	flow_offload_free(flow);
err_flow_alloc:
	if (!(ct->status & IPS_NAT_MASK))
		dst_release(route.tuple[dir].dst);
	dst_release(route.tuple[!dir].dst);
err_flow_route:
	clear_bit(IPS_OFFLOAD_BIT, &ct->status);

	return XT_CONTINUE;
}

static int flowoffload_chk(const struct xt_tgchk_param *par)
{
	struct xt_flowoffload_target_info *info = par->targinfo;

	if (info->flags & ~XT_FLOWOFFLOAD_MASK)
		return -EINVAL;

	return 0;
}

static struct xt_target offload_tg_reg __read_mostly = {
	.family		= NFPROTO_UNSPEC,
	.name		= "FLOWOFFLOAD",
	.revision	= 0,
	.targetsize	= sizeof(struct xt_flowoffload_target_info),
	.usersize	= sizeof(struct xt_flowoffload_target_info),
	.checkentry	= flowoffload_chk,
	.target		= flowoffload_tg,
	.me		= THIS_MODULE,
};

static int flow_offload_netdev_event(struct notifier_block *this,
				     unsigned long event, void *ptr)
{
	struct xt_flowoffload_hook *hook0, *hook1;
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	spin_lock_bh(&hooks_lock);

	xt_LOG(Log_debug, "xt_flowoffload: remove hook for %s due to NETDEV_UNREGISTER\n", dev->name);

	hook0 = flow_offload_lookup_hook(&flowtable[0], dev);
	if (hook0)
		hlist_del(&hook0->list);

	hook1 = flow_offload_lookup_hook(&flowtable[1], dev);
	if (hook1)
		hlist_del(&hook1->list);
	spin_unlock_bh(&hooks_lock);

	if (hook0) {
		nf_unregister_net_hook(hook0->net, &hook0->ops);
		kfree(hook0);
	}

	if (hook1) {
		nf_unregister_net_hook(hook1->net, &hook1->ops);
		kfree(hook1);
	}

	nf_flow_table_cleanup(dev);

	return NOTIFY_DONE;
}

static struct notifier_block flow_offload_netdev_notifier = {
	.notifier_call	= flow_offload_netdev_event,
};

static int nf_flow_rule_route_inet(struct net *net,
				   const struct flow_offload *flow,
				   enum flow_offload_tuple_dir dir,
				   struct nf_flow_rule *flow_rule)
{
	const struct flow_offload_tuple *flow_tuple = &flow->tuplehash[dir].tuple;
	int err;

	switch (flow_tuple->l3proto) {
	case NFPROTO_IPV4:
		err = nf_flow_rule_route_ipv4(net, flow, dir, flow_rule);
		break;
	case NFPROTO_IPV6:
		err = nf_flow_rule_route_ipv6(net, flow, dir, flow_rule);
		break;
	default:
		err = -1;
		break;
	}

	return err;
}

static struct nf_flowtable_type flowtable_inet = {
	.family		= NFPROTO_INET,
	.init		= nf_flow_table_init,
	.setup		= nf_flow_table_offload_setup,
	.action		= nf_flow_rule_route_inet,
	.free		= nf_flow_table_free,
	.hook		= xt_flowoffload_net_hook,
	.owner		= THIS_MODULE,
};

static int init_flowtable(struct xt_flowoffload_table *tbl)
{
	INIT_DELAYED_WORK(&tbl->work, xt_flowoffload_hook_work);
	tbl->ft.type = &flowtable_inet;

	return nf_flow_table_init(&tbl->ft);
}

#ifdef CONFIG_OVS_SKIP_ACCEL_ACTION

static struct nf_hook_ops flowoff_hook_ops;
static struct dentry *xt_flowoff_debugfs_dir;
static struct dentry *xt_flowoff_debugfs_enable;
static struct dentry *xt_flowoff_debugfs_hooks;
static struct dentry *xt_flowoff_debugfs_dscp;
static struct dentry *xt_flowoff_debugfs_flush_entry;
extern int flush_flows_by_mac(char *mac_address);
extern cb_ovs_helper_get_ufid_len ovs_get_ufid_len;


// nf_dev_forward_path -> nf_dev_fill_forward_path() mix copy function
static int nf_dev_forward_path_ovs(struct nf_flow_route *route,
				const struct nf_conn *ct,
				enum ip_conntrack_dir dir,
				struct net_device **devs, struct net_device **real_devs, unsigned char ha_l2[][ETH_ALEN])
{
	const struct dst_entry *dst = route->tuple[dir].dst;
	struct net_device_path_stack stack;
	struct nf_forward_info info = {};
	unsigned char ha[ETH_ALEN];
	int i;


	// for openvswitch
	if(real_devs && ha_l2)
	{
		if (!nf_is_valid_ether_device(dst->dev)){
			xt_LOG(Log_err, "%s/%d : nf_is_valid_ether_device() return false\n", __func__, __LINE__);

			memcpy(ha, ha_l2[dir], ETH_ALEN);

			if(dev_fill_forward_path_for_ovs_l2(dst->dev, ha, &stack, real_devs[dir]) >= 0){
				nf_dev_path_info(&stack, &info, ha);
			}
		}
	}
	else {
		return -1;
	}

	devs[!dir] = (struct net_device *)info.indev;
	if (!info.indev)
		return -1;

	route->tuple[!dir].in.ifindex = info.indev->ifindex;
	for (i = 0; i < info.num_encaps; i++) {
		route->tuple[!dir].in.encap[i].id = info.encap[i].id;
		route->tuple[!dir].in.encap[i].proto = info.encap[i].proto;
	}
	route->tuple[!dir].in.num_encaps = info.num_encaps;
	route->tuple[!dir].in.ingress_vlans = info.ingress_vlans;

	if (info.xmit_type == FLOW_OFFLOAD_XMIT_DIRECT) {
		memcpy(route->tuple[dir].out.h_source, info.h_source, ETH_ALEN);
		memcpy(route->tuple[dir].out.h_dest, info.h_dest, ETH_ALEN);
		route->tuple[dir].out.ifindex = info.outdev->ifindex;
		route->tuple[dir].out.hw_ifindex = info.hw_outdev->ifindex;
		route->tuple[dir].xmit_type = info.xmit_type;
	}

	return 0;
}

static int
xt_flowoffload_route_dir_handler(struct nf_flow_route *route, const struct nf_conn *ct,
			 enum ip_conntrack_dir dir,
			 const struct nf_hook_state *state, int ifindex,
			 struct net_device **devs)
{
	struct dst_entry *dst = NULL;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	switch (state->pf) {
	case NFPROTO_IPV4:
		fl.u.ip4.daddr = ct->tuplehash[!dir].tuple.src.u3.ip;
		fl.u.ip4.flowi4_oif = ifindex;
		break;
	case NFPROTO_IPV6:
		fl.u.ip6.saddr = ct->tuplehash[!dir].tuple.dst.u3.in6;
		fl.u.ip6.daddr = ct->tuplehash[!dir].tuple.src.u3.in6;
		fl.u.ip6.flowi6_oif = ifindex;
		break;
	}

	nf_route(state->net, &dst, &fl, false, state->pf);
	if (!dst)
		return -ENOENT;

	nf_default_forward_path(route, dst, dir, devs);

	return 0;
}

// xt_flowoffload_route_bridge() copy
static int
xt_flowoffload_route_ovs(struct sk_buff *skb, const struct nf_conn *ct,
		     const struct nf_hook_state *state,
		     struct nf_flow_route *route, enum ip_conntrack_dir dir,
		     struct net_device **devs, struct net_device **real_devs, unsigned char ha[][ETH_ALEN])
{
	int ret;

	ret = xt_flowoffload_route_dir_handler(route, ct, dir, state,
				       devs[dir]->ifindex,
				       devs);
	if (ret)
		return ret;

	ret = xt_flowoffload_route_dir_handler(route, ct, !dir, state,
				       devs[!dir]->ifindex,
				       devs);
	if (ret)
		goto err_route_dir1;

	if (route->tuple[dir].xmit_type	== FLOW_OFFLOAD_XMIT_NEIGH &&
	    route->tuple[!dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH) {
#if 1
		if (nf_dev_forward_path_ovs(route, ct, dir, devs, real_devs, ha) || 
		    nf_dev_forward_path_ovs(route, ct, !dir, devs, real_devs, ha)) {
#endif 
			ret = -1;
			goto err_route_dir2;
		}
	}
	return 0;

err_route_dir2:
	dst_release(route->tuple[!dir].dst);
err_route_dir1:
	dst_release(route->tuple[dir].dst);
	return ret;
}

static void
xt_flowoffload_cleanup_all_hooks(struct xt_flowoffload_table *table)
{
	struct xt_flowoffload_hook *hook;

try_restart:
	spin_lock_bh(&hooks_lock);
	hlist_for_each_entry(hook, &table->hooks, list) {
		hlist_del(&hook->list);
		spin_unlock_bh(&hooks_lock);
		if (table->ft.flags & NF_FLOWTABLE_HW_OFFLOAD)
			table->ft.type->setup(&table->ft, hook->ops.dev,
					      FLOW_BLOCK_UNBIND);
		nf_unregister_net_hook(hook->net, &hook->ops);
		kfree(hook);
		goto try_restart;
	}
	spin_unlock_bh(&hooks_lock);
}

static ssize_t flowoff_read_enable(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	char buf[4] = {0};
	snprintf(buf, sizeof(buf), "%d\n", xt_flowoff_enable);
	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

static ssize_t flowoff_write_enable(struct file *file,
					      const char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	ssize_t rc;
	char buf[4] = {0};

	/* filter partial writes and invalid commands */
	if (*ppos != 0 || count >= sizeof(buf) || count == 0)
		return -EINVAL;

	rc = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);
	if (rc < 0)
		return rc;

	/* drop the possible '\n' from the end */
	if (buf[*ppos - 1] == '\n')
		buf[*ppos - 1] = '\0';

	sscanf(buf, "%hhu", &xt_flowoff_enable);

	if(!xt_flowoff_enable)
	{
		xt_LOG(Log_debug, "xt_flowoffload: clean up all hooks\n");
		xt_flowoffload_cleanup_all_hooks(&flowtable[0]);
		xt_flowoffload_cleanup_all_hooks(&flowtable[1]);
	}

	return count;
}

static const struct file_operations fops_file_enable = {
	.read = flowoff_read_enable,
	.write = flowoff_write_enable,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int get_ingress_hooks(struct xt_flowoffload_table *table, char *data)
{
	struct xt_flowoffload_hook *hook;
	int strcount = 0;

	spin_lock_bh(&hooks_lock);
	hlist_for_each_entry(hook, &table->hooks, list) {
		strncpy(data + strcount, hook->ops.dev->name, strlen(hook->ops.dev->name));
		strcount = strcount + strlen(hook->ops.dev->name);
		*(data + strcount) = '\n';
		strcount++;
	}
	spin_unlock_bh(&hooks_lock);
	return strcount;
}

static ssize_t flowoff_read_hooks(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	char buf[512] = {0};
	int count1 = 0, count2 = 0;

	count1 = get_ingress_hooks(&flowtable[0], &buf[0]);
	if(count1 > 0)
		count2 = count1 - 1;
	else
		count2 = 0;

	count2 = get_ingress_hooks(&flowtable[1], &buf[count2]);
	buf[count1 + count2] = '\0';

	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

static ssize_t flowoff_write_hooks(struct file *file,
					      const char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	ssize_t rc;
	char buf[16] = {0};

	/* filter partial writes and invalid commands */
	if (*ppos != 0 || count >= sizeof(buf) || count == 0)
		return -EINVAL;

	rc = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);
	if (rc < 0)
		return rc;

	/* drop the possible '\n' from the end */
	if (buf[*ppos - 1] == '\n')
		buf[*ppos - 1] = '\0';

	if (!strcmp(buf, "clear")) {
		xt_flowoffload_cleanup_all_hooks(&flowtable[0]);
		xt_flowoffload_cleanup_all_hooks(&flowtable[1]);
	}
	return count;
}

static int
xt_flowoffload_route_nat_handler(struct sk_buff *skb, const struct nf_conn *ct,
			 const struct nf_hook_state *state,
			 struct nf_flow_route *route, enum ip_conntrack_dir dir,
			 struct net_device **devs)
{
	struct dst_entry *this_dst = skb_dst(skb);
	struct dst_entry *other_dst = NULL;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	switch (state->pf) {
	case NFPROTO_IPV4:
		fl.u.ip4.daddr = ct->tuplehash[dir].tuple.src.u3.ip;
		fl.u.ip4.flowi4_oif = state->in->ifindex;
		break;
	case NFPROTO_IPV6:
		fl.u.ip6.saddr = ct->tuplehash[!dir].tuple.dst.u3.in6;
		fl.u.ip6.daddr = ct->tuplehash[dir].tuple.src.u3.in6;
		fl.u.ip6.flowi6_oif = state->in->ifindex;
		break;
	}

	nf_route(state->net, &other_dst, &fl, false, state->pf);
	if (!other_dst)
		return -ENOENT;

	nf_default_forward_path(route, this_dst, dir, devs);
	nf_default_forward_path(route, other_dst, !dir, devs);

	if (route->tuple[dir].xmit_type	== FLOW_OFFLOAD_XMIT_NEIGH &&
	    route->tuple[!dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH) {
		if (nf_dev_forward_path(skb, route, ct, dir, devs))
			return -1;
		if (nf_dev_forward_path(skb, route, ct, !dir, devs))
			return -1;
	}

	return 0;
}

static int
xt_flowoffload_route_bridge_handler(struct sk_buff *skb, const struct nf_conn *ct,
			    const struct nf_hook_state *state,
			    struct nf_flow_route *route, enum ip_conntrack_dir dir,
			    struct net_device **devs)
{
	int ret;

	ret = xt_flowoffload_route_dir_handler(route, ct, dir, state,
				       devs[dir]->ifindex,
				       devs);
	if (ret)
		return ret;

	ret = xt_flowoffload_route_dir_handler(route, ct, !dir, state,
				       devs[!dir]->ifindex,
				       devs);
	if (ret)
		goto err_route_dir1;

	if (route->tuple[dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH &&
	    route->tuple[!dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH) {
		if (nf_dev_forward_path(skb, route, ct, dir, devs) ||
		    nf_dev_forward_path(skb, route, ct, !dir, devs)) {
			ret = -1;
			goto err_route_dir2;
		}
	}

	return 0;

err_route_dir2:
	dst_release(route->tuple[!dir].dst);
err_route_dir1:
	dst_release(route->tuple[dir].dst);
	return ret;
}

static const struct file_operations fops_file_hooks = {
	.read = flowoff_read_hooks,
	.write = flowoff_write_hooks,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t flowoff_read_flush(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t flowoff_write_flush(struct file *file,
					      const char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	ssize_t rc;
	char buf[32] = {0};
	char mac[ETH_ALEN];

	/* filter partial writes and invalid commands */
	if (*ppos != 0 || count >= sizeof(buf) || count == 0)
		return -EINVAL;

	rc = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);
	if (rc < 0)
		return rc;

	/* drop the possible '\n' from the end */
	if (buf[*ppos - 1] == '\n')
		buf[*ppos - 1] = '\0';

	if (!strncmp(buf, "ALL", strlen("ALL"))) {
		flush_flows_by_mac(NULL);
	}
	else if (sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2],
			&mac[3], &mac[4], &mac[5]) == ETH_ALEN) {
		flush_flows_by_mac(mac);
	}

	return count;
}

static const struct file_operations fops_file_flush = {
	.read = flowoff_read_flush,
	.write = flowoff_write_flush,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

	static bool
skip_accel_check(struct sk_buff *skb, const struct nf_hook_state *state, struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	struct tcphdr *tcph = NULL;
	enum ip_conntrack_dir ct_dir;
	struct nf_conn_acct *acct = NULL;
	long long packets = 0;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	u8 tos = 0;
	u16 sport = 0;

	xt_LOG(Log_trace, "[skip_accel_check] flowoffload hook, skb (%p) nfct(%lx) ct mark(%x) skip_accel (%d) hash(%x) zoneid (%x)\n", skb, skb->_nfct, ct->mark, skb->ovs_skip_accel, skb_get_hash(skb), ct->zone.id);
	if (!xt_flowoff_enable)
	{
		xt_LOG(Log_trace, "[skip_accel_check] skb (%p) flow offload disable\n", skb);
		/*
		   TO DO : clean flow offload entries and remove ingress hook
		   */
		return 1;
	}

	if (xt_flowoffload_skip(skb, state->pf))
	{
		xt_LOG(Log_trace, "[skip_accel_check] skb (%p) flow offload skip, return\n", skb);
		return 1;
	}

	if (skb->ovs_skip_accel == 1)
	{
		xt_LOG(Log_trace, "[skip_accel_check] skb (%p) skip accel, return\n", skb);
		return 1;
	}

	ct_dir = CTINFO2DIR(ctinfo);
	switch (skb->protocol) {
		case htons(ETH_P_IP):
			iph = ip_hdr(skb);

			tos = iph->tos;
			xt_LOG(Log_trace, "[skip_accel_check] tuple : %u %pI4:%hu -> %pI4:%hu , iden (%x), hash(%x), ufid (%x%x%x%x), ufid_len (%d), tos(%x)\n",
					ct->tuplehash[ct_dir].tuple.dst.protonum,
					&ct->tuplehash[ct_dir].tuple.src.u3.ip, ntohs(ct->tuplehash[ct_dir].tuple.src.u.all),
					&ct->tuplehash[ct_dir].tuple.dst.u3.ip, ntohs(ct->tuplehash[ct_dir].tuple.dst.u.all),
					iph->id, skb_get_hash(skb),
					ct->tuplehash[ct_dir].tuple.ovs.ufid[0], ct->tuplehash[ct_dir].tuple.ovs.ufid[1],
					ct->tuplehash[ct_dir].tuple.ovs.ufid[2], ct->tuplehash[ct_dir].tuple.ovs.ufid[3], ct->tuplehash[ct_dir].tuple.ovs.ufid_len, tos);
			break;
		case htons(ETH_P_IPV6):
			ip6h = ipv6_hdr(skb);
			tos = ipv6_get_dsfield(ip6h);

			if ((ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP) && (ct->proto.tcp.state == TCP_CONNTRACK_ESTABLISHED))
			{
				tcph = tcp_hdr(skb);
				xt_LOG(Log_trace, "[skip_accel_check] tuple : %u %pI6:%hu -> %pI6:%hu, tcp seq:%x, tcp ack seq: %x, hash(%x), tos(%x)\n",
						ct->tuplehash[ct_dir].tuple.dst.protonum,
						&ct->tuplehash[ct_dir].tuple.src.u3.ip, ntohs(ct->tuplehash[ct_dir].tuple.src.u.all),
						&ct->tuplehash[ct_dir].tuple.dst.u3.ip, ntohs(ct->tuplehash[ct_dir].tuple.dst.u.all),
						tcph->seq, tcph->ack_seq, skb_get_hash(skb), tos);
			}
			else {
				xt_LOG(Log_trace, "[skip_accel_check] tuple : %u %pI6:%hu -> %pI6:%hu, hash(%x) tcp not established yet.\n",
						ct->tuplehash[ct_dir].tuple.dst.protonum,
						&ct->tuplehash[ct_dir].tuple.src.u3.ip, ntohs(ct->tuplehash[ct_dir].tuple.src.u.all),
						&ct->tuplehash[ct_dir].tuple.dst.u3.ip, ntohs(ct->tuplehash[ct_dir].tuple.dst.u.all),
						skb_get_hash(skb));
			}
			break;
		default:
			break;
	}

	if(tos != 0)
	{
		spin_lock_bh(&ct->lock);
		ct->tuplehash[ct_dir].tuple.tos = tos;
		ct->tuplehash[!ct_dir].tuple.tos = tos;
		spin_unlock_bh(&ct->lock);
	}

	sport = ntohs(ct->tuplehash[ct_dir].tuple.src.u.all);
	/* Forever slowpath DHCP, DNS.. */
	if (ip_hdr(skb)->protocol == IPPROTO_UDP &&
			(sport == 53 ||
			 sport == 67 ||
			 sport == 68 ||
			 sport == 547))
	{
		xt_LOG(Log_trace, "[skip_accel_check] skb (%p) hit udp sport 53/67/68/547\n", skb);
		return 1;
	}


	if(ct->mark == 0)
	{
		acct = nf_conn_acct_find(ct);
		if (acct != NULL)
		{
			struct nf_conn_counter *counter = acct->counter;
			packets = atomic64_read(&counter[IP_CT_DIR_ORIGINAL].packets);
			packets += atomic64_read(&counter[IP_CT_DIR_REPLY].packets);
			xt_LOG(Log_trace, "[skip_accel_check] hash (%x), counter (%lld)\n", skb_get_hash(skb), packets);
		}
		if(packets <= xt_flowoff_deferral)
		{
			xt_LOG(Log_trace, "[skip_accel_check] skb (%p) packets (%lld) less than deferral limit (%d), return\n", skb, packets, xt_flowoff_deferral);
			return 1;
		}
	}
	//
	// Changing the CT mark comparing condition. The packet entr fast path if it's not in the inspect or drop states, otherwise go to fast path.
	// The CT mark value will be 10, 20, 30 or 40 after enable App Prioriziation, so we can't just use mark 2 to decide the packet go fast path or not.
	//
	else if ((ct->mark == xt_flowoff_mark_inspect) || (ct->mark == xt_flowoff_mark_drop))
	{
		xt_LOG(Log_trace, "[skip_accel_check] skb (%p), hash (%x) ct mark is 1 or 3, return\n", skb, skb_get_hash(skb));
		return 1;
	}
	return 0;
}

static ssize_t flowoff_read_dscp(struct file *file,
		char __user *user_buf,
		size_t count, loff_t *ppos)
{
	char buf[512] = {0};

	sprintf(buf, "%d:%d;%d:%d;%d:%d;%d:%d;%d:%d;%d:%d;%d:%d;%d:%d;\n",
			dscp_mapping[0].mark, dscp_mapping[0].dscp,
			dscp_mapping[1].mark, dscp_mapping[1].dscp,
			dscp_mapping[2].mark, dscp_mapping[2].dscp,
			dscp_mapping[3].mark, dscp_mapping[3].dscp,
			dscp_mapping[4].mark, dscp_mapping[4].dscp,
			dscp_mapping[5].mark, dscp_mapping[5].dscp,
			dscp_mapping[6].mark, dscp_mapping[6].dscp,
			dscp_mapping[7].mark, dscp_mapping[7].dscp);

	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

static ssize_t flowoff_write_dscp(struct file *file,
		const char __user *user_buf,
		size_t count, loff_t *ppos)
{
	ssize_t rc;
	char buf[512] = {0};

	/* filter partial writes and invalid commands */
	if (*ppos != 0 || count >= sizeof(buf) || count == 0)
		return -EINVAL;
	rc = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);
	if (rc < 0)
		return rc;

	/* drop the possible '\n' from the end */
	if (buf[*ppos - 1] == '\n')
		buf[*ppos - 1] = '\0';

	sscanf(buf, "%d:%d;%d:%d;%d:%d;%d:%d;%d:%d;%d:%d;%d:%d;%d:%d;\n",
			&dscp_mapping[0].mark, &dscp_mapping[0].dscp,
			&dscp_mapping[1].mark, &dscp_mapping[1].dscp,
			&dscp_mapping[2].mark, &dscp_mapping[2].dscp,
			&dscp_mapping[3].mark, &dscp_mapping[3].dscp,
			&dscp_mapping[4].mark, &dscp_mapping[4].dscp,
			&dscp_mapping[5].mark, &dscp_mapping[5].dscp,
			&dscp_mapping[6].mark, &dscp_mapping[6].dscp,
			&dscp_mapping[7].mark, &dscp_mapping[7].dscp);

	return count;
}

static const struct file_operations fops_file_dscp = {
	.read = flowoff_read_dscp,
	.write = flowoff_write_dscp,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};
 
extern struct flow_offload *flow_offload_alloc(struct nf_conn *ct);
extern void flow_offload_free(struct flow_offload *flow);
extern void flow_offload_teardown_by_tuple(struct flow_offload_tuple *tuple);

void flow_offload_flush_by_tuple(struct flow_offload_tuple *ft)
{
	struct xt_flowoffload_table *table;
	struct xt_flowoffload_hook *hook;
	table = &flowtable[XT_FLOWOFFLOAD_HW];

	spin_lock_bh(&hooks_lock);
	hlist_for_each_entry(hook, &table->hooks, list) {
		spin_unlock_bh(&hooks_lock);

		if(ft != NULL){
			ft->iifidx = hook->ops.dev->ifindex;
			/* Release spin_lock_bh since the function calls mutex_lock */
			flow_offload_teardown_by_tuple(ft);
		}
		spin_lock_bh(&hooks_lock);
	}
	spin_unlock_bh(&hooks_lock);
}

void xt_flowoffload_flush_ct_flow(struct nf_conn *ct)
{

	struct flow_offload *flow;
	struct flow_offload_tuple *ft;

	flow = flow_offload_alloc(ct);
	if(flow != NULL){
		ft = &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple;
		flow_offload_flush_by_tuple(ft);
		flow_offload_free(flow);
	}
}
EXPORT_SYMBOL_GPL(xt_flowoffload_flush_ct_flow);

/*
	nf_flowoffload_handler is copied from flowoffload_tg and need to sync with flowoffload_tg if it changed.
*/
static unsigned int
nf_flowoffload_handler(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state, struct net_device **real_devs)
{
	struct xt_flowoffload_table *table;
	struct tcphdr *tcph = NULL;
	enum ip_conntrack_info ctinfo;
	enum ip_conntrack_dir dir;
	struct nf_flow_route route = {};
	struct flow_offload *flow = NULL;
	struct net_device *devs[2] = {};
	struct nf_conn *ct;
	struct net *net;
	unsigned char ha[2][ETH_ALEN] = {};
	struct ethhdr *eth = 0;
	enum ip_conntrack_dir ct_dir;



	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL)
		return NF_ACCEPT;

	if (skip_accel_check(skb, state, ct, ctinfo))
		return NF_ACCEPT;

	switch (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum) {
	case IPPROTO_TCP:
		if (ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED)
			return NF_ACCEPT;

		tcph = tcp_hdr(skb);
		if (unlikely(!tcph || tcph->fin || tcph->rst))
			return NF_ACCEPT;

		break;
	case IPPROTO_UDP:
		break;
	default:
		return NF_ACCEPT;
	}

	if (nf_ct_ext_exist(ct, NF_CT_EXT_HELPER) ||
	    ct->status & IPS_SEQ_ADJUST)
		return NF_ACCEPT;

	if (!nf_ct_is_confirmed(ct))
		return NF_ACCEPT;

	if (test_and_set_bit(IPS_OFFLOAD_BIT, &ct->status))
		return NF_ACCEPT;

	dir = CTINFO2DIR(ctinfo);

	devs[dir] = state->out;
	devs[!dir] = state->in;

	if (!devs[dir] || !devs[!dir])
		return NF_ACCEPT;

	//
	// Waitting for flow exist in datapath of openflow, only check for the packets from OVS or to OVS
	// These conditions are for the 2 entry point :
	// 1. through ip_recv : netif_is_ovs_master(devs[ct_dir]) || netif_is_ovs_master(devs[!ct_dir])
	// 2. through ovs : real_devs, the do_output of action will fill this array.
	//
	ct_dir = CTINFO2DIR(ctinfo);
	if(netif_is_ovs_master(devs[ct_dir]) || netif_is_ovs_master(devs[!ct_dir]) || real_devs)
	{
		if(ct->tuplehash[ct_dir].tuple.ovs.ufid_len == 0)
			return NF_ACCEPT;

		if (ct->tuplehash[ct_dir].tuple.dst.protonum == IPPROTO_TCP) {
			if(ct->tuplehash[!ct_dir].tuple.ovs.ufid_len == 0)
				return NF_ACCEPT;
		}
	}

	if(real_devs)
	{
		// Accel for OVS bridge forwarding
		eth = skb_eth_hdr(skb);
		if(eth)
		{
			ether_addr_copy(ha[dir], eth->h_dest);
			ether_addr_copy(ha[!dir], eth->h_source);
		}
		else
			goto err_flow_route;
#if 1 // plume add
		if (xt_flowoffload_route_ovs(skb, ct, state, &route, dir, devs, real_devs, ha) < 0)
			goto err_flow_route;
#endif // plume add
	}
	else
	{
		if (ct->status & IPS_NAT_MASK) {
			if (xt_flowoffload_route_nat_handler(skb, ct, state, &route, dir, devs) < 0)
				goto err_flow_route;
		} else {
			if (xt_flowoffload_route_bridge_handler(skb, ct, state, &route, dir, devs) < 0)
				goto err_flow_route;
		}
	}

	// To skip sw/hw fast path for GRE interfaces
	if (netif_is_gretap(devs[0]) || netif_is_gretap(devs[1]) || netif_is_ip6gretap(devs[0]) || netif_is_ip6gretap(devs[1])) {
		goto err_flow_route;
	}

	flow = flow_offload_alloc(ct);
	if (!flow)
		goto err_flow_alloc;

	if (flow_offload_route_init(flow, &route) < 0)
		goto err_flow_add;

	if (xt_flowoffload_dscp_init(skb, flow, dir) < 0)
		goto err_flow_add;

#if 1 // opensync-305
        if (xt_flowoffload_set_hqos(skb, flow, dir) < 0)
                goto err_flow_add;
#endif

	if (tcph) {
		ct->proto.tcp.seen[0].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		ct->proto.tcp.seen[1].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	table = &flowtable[XT_FLOWOFFLOAD_HW];

	net = read_pnet(&table->ft.net);	

	if (!net)
		write_pnet(&table->ft.net, state->net);

	//
	// Changing the source MAC address for the GRE traffic.
	// The source MAC should not be the one of br-home, otherwise all the GUARD function will be abnormal for the traffic for Leaf nodes.
	// The source MAC and dest MAC should be same as the one which send out from client when the traffic from OVS bridge.
	//
	if(real_devs)
	{
		if (netif_is_gretap(devs[0]) || netif_is_gretap(devs[1])) {
			eth = skb_eth_hdr(skb);
			if(eth)
			{
				ether_addr_copy(flow->tuplehash[dir].tuple.out.h_source, eth->h_source);
				ether_addr_copy(flow->tuplehash[dir].tuple.out.h_dest, eth->h_dest);
				ether_addr_copy(flow->tuplehash[!dir].tuple.out.h_source, eth->h_dest);
				ether_addr_copy(flow->tuplehash[!dir].tuple.out.h_dest, eth->h_source);
			}
		}
	}

	if (flow_offload_add(&table->ft, flow) < 0)
		goto err_flow_add;

	xt_flowoffload_check_device(table, devs[0]);
	xt_flowoffload_check_device(table, devs[1]);

	if (!(ct->status & IPS_NAT_MASK))
		dst_release(route.tuple[dir].dst);
	dst_release(route.tuple[!dir].dst);

	return NF_ACCEPT;

err_flow_add:
	flow_offload_free(flow);
err_flow_alloc:
	if (!(ct->status & IPS_NAT_MASK))
		dst_release(route.tuple[dir].dst);
	dst_release(route.tuple[!dir].dst);
err_flow_route:
	clear_bit(IPS_OFFLOAD_BIT, &ct->status);

	return NF_ACCEPT;
}

EXPORT_SYMBOL_GPL(nf_flowoffload_handler);

unsigned int
nf_flowoffload_handler_hook(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	return nf_flowoffload_handler(priv, skb, state, NULL);
}
#endif

static int __init xt_flowoffload_tg_init(void)
{
	int ret;

	register_netdevice_notifier(&flow_offload_netdev_notifier);

	ret = init_flowtable(&flowtable[0]);
	if (ret)
		return ret;

	ret = init_flowtable(&flowtable[1]);
	if (ret)
		goto cleanup;

	flowtable[1].ft.flags = NF_FLOWTABLE_HW_OFFLOAD | NF_FLOWTABLE_COUNTER;

	ret = xt_register_target(&offload_tg_reg);
	if (ret)
		goto cleanup2;

#ifdef CONFIG_OVS_SKIP_ACCEL_ACTION
	flowoff_hook_ops.hook = (nf_hookfn*)nf_flowoffload_handler_hook;
	flowoff_hook_ops.hooknum = NF_INET_FORWARD;
	flowoff_hook_ops.pf = NFPROTO_INET;
	flowoff_hook_ops.priority = NF_IP_PRI_LAST; // set the priority
	nf_register_net_hook(&init_net, &flowoff_hook_ops);

	xt_flowoff_debugfs_dir = debugfs_create_dir("xt_flowoffload",NULL);
	xt_flowoff_debugfs_enable = debugfs_create_file("enable", 0666, xt_flowoff_debugfs_dir, NULL, &fops_file_enable);
	xt_flowoff_debugfs_hooks = debugfs_create_file("hooks", 0666, xt_flowoff_debugfs_dir, NULL, &fops_file_hooks);
	xt_flowoff_debugfs_flush_entry = debugfs_create_file("flush", 0666, xt_flowoff_debugfs_dir, NULL, &fops_file_flush);
	xt_flowoff_debugfs_dscp = debugfs_create_file("dscp_mapping", 0666, xt_flowoff_debugfs_dir, NULL, &fops_file_dscp);
	debugfs_create_u32("deferral", 0666, xt_flowoff_debugfs_dir, &xt_flowoff_deferral);
	debugfs_create_u8("debug", 0666, xt_flowoff_debugfs_dir, &xt_flowoff_debug);
	debugfs_create_u8("drop_mark", 0666, xt_flowoff_debugfs_dir, &xt_flowoff_mark_drop);
	debugfs_create_u8("inspect_mark", 0666, xt_flowoff_debugfs_dir, &xt_flowoff_mark_inspect);
#endif
	return 0;

cleanup2:
	nf_flow_table_free(&flowtable[1].ft);
cleanup:
	nf_flow_table_free(&flowtable[0].ft);
	return ret;
}

static void __exit xt_flowoffload_tg_exit(void)
{
	xt_unregister_target(&offload_tg_reg);
	unregister_netdevice_notifier(&flow_offload_netdev_notifier);
	nf_flow_table_free(&flowtable[0].ft);
	nf_flow_table_free(&flowtable[1].ft);
#ifdef CONFIG_OVS_SKIP_ACCEL_ACTION
	debugfs_remove_recursive(xt_flowoff_debugfs_dir);
#endif
}

MODULE_LICENSE("GPL");
module_init(xt_flowoffload_tg_init);
module_exit(xt_flowoffload_tg_exit);

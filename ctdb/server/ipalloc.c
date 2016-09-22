/*
   ctdb ip takeover code

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Martin Schwenke  2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <talloc.h>

#include "replace.h"
#include "system/network.h"

#include "lib/util/debug.h"

#include "common/logging.h"
#include "common/rb_tree.h"

#include "server/ipalloc_private.h"

/* Initialise main ipalloc state and sub-structures */
struct ipalloc_state *
ipalloc_state_init(TALLOC_CTX *mem_ctx,
		   uint32_t num_nodes,
		   enum ipalloc_algorithm algorithm,
		   bool no_ip_failback,
		   uint32_t *force_rebalance_nodes)
{
	struct ipalloc_state *ipalloc_state =
		talloc_zero(mem_ctx, struct ipalloc_state);
	if (ipalloc_state == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Out of memory\n"));
		return NULL;
	}

	ipalloc_state->num = num_nodes;

	ipalloc_state->noiptakeover =
		talloc_zero_array(ipalloc_state,
				  bool,
				  ipalloc_state->num);
	if (ipalloc_state->noiptakeover == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Out of memory\n"));
		goto fail;
	}
	ipalloc_state->noiphost =
		talloc_zero_array(ipalloc_state,
				  bool,
				  ipalloc_state->num);
	if (ipalloc_state->noiphost == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Out of memory\n"));
		goto fail;
	}

	ipalloc_state->algorithm = algorithm;
	ipalloc_state->no_ip_failback = no_ip_failback;
	ipalloc_state->force_rebalance_nodes = force_rebalance_nodes;

	return ipalloc_state;
fail:
	talloc_free(ipalloc_state);
	return NULL;
}

static void *add_ip_callback(void *parm, void *data)
{
	struct public_ip_list *this_ip = parm;
	struct public_ip_list *prev_ip = data;

	if (prev_ip == NULL) {
		return parm;
	}
	if (this_ip->pnn == -1) {
		this_ip->pnn = prev_ip->pnn;
	}

	return parm;
}

static int getips_count_callback(void *param, void *data)
{
	struct public_ip_list **ip_list = (struct public_ip_list **)param;
	struct public_ip_list *new_ip = (struct public_ip_list *)data;

	new_ip->next = *ip_list;
	*ip_list     = new_ip;
	return 0;
}

/* Nodes only know about those public addresses that they are
 * configured to serve and no individual node has a full list of all
 * public addresses configured across the cluster.  Therefore, a
 * merged list of all public addresses needs to be built so that IP
 * allocation can be done. */
static struct public_ip_list *
create_merged_ip_list(struct ipalloc_state *ipalloc_state)
{
	int i, j;
	struct public_ip_list *ip_list;
	struct ctdb_public_ip_list *public_ips;
	struct trbt_tree *ip_tree;

	ip_tree = trbt_create(ipalloc_state, 0);

	if (ipalloc_state->known_public_ips == NULL) {
		DEBUG(DEBUG_ERR, ("Known public IPs not set\n"));
		return NULL;
	}

	for (i=0; i < ipalloc_state->num; i++) {

		public_ips = &ipalloc_state->known_public_ips[i];

		for (j=0; j < public_ips->num; j++) {
			struct public_ip_list *tmp_ip;

			/* This is returned as part of ip_list */
			tmp_ip = talloc_zero(ipalloc_state, struct public_ip_list);
			if (tmp_ip == NULL) {
				DEBUG(DEBUG_ERR,
				      (__location__ " out of memory\n"));
				talloc_free(ip_tree);
				return NULL;
			}

			/* Do not use information about IP addresses hosted
			 * on other nodes, it may not be accurate */
			if (public_ips->ip[j].pnn == i) {
				tmp_ip->pnn = public_ips->ip[j].pnn;
			} else {
				tmp_ip->pnn = -1;
			}
			tmp_ip->addr = public_ips->ip[j].addr;
			tmp_ip->next = NULL;

			trbt_insertarray32_callback(ip_tree,
				IP_KEYLEN, ip_key(&public_ips->ip[j].addr),
				add_ip_callback,
				tmp_ip);
		}
	}

	ip_list = NULL;
	trbt_traversearray32(ip_tree, IP_KEYLEN, getips_count_callback, &ip_list);
	talloc_free(ip_tree);

	return ip_list;
}

static bool all_nodes_are_disabled(struct ctdb_node_map *nodemap)
{
	int i;

	for (i=0;i<nodemap->num;i++) {
		if (!(nodemap->node[i].flags &
		      (NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED))) {
			/* Found one completely healthy node */
			return false;
		}
	}

	return true;
}

/* Set internal flags for IP allocation:
 *   Clear ip flags
 *   Set NOIPTAKOVER ip flags from per-node NoIPTakeover tunable
 *   Set NOIPHOST ip flag for each INACTIVE node
 *   if all nodes are disabled:
 *     Set NOIPHOST ip flags from per-node NoIPHostOnAllDisabled tunable
 *   else
 *     Set NOIPHOST ip flags for disabled nodes
 */
void ipalloc_set_node_flags(struct ipalloc_state *ipalloc_state,
			    struct ctdb_node_map *nodemap,
			    uint32_t *tval_noiptakeover,
			    uint32_t *tval_noiphostonalldisabled)
{
	int i;

	for (i=0;i<nodemap->num;i++) {
		/* Can not take IPs on node with NoIPTakeover set */
		if (tval_noiptakeover[i] != 0) {
			ipalloc_state->noiptakeover[i] = true;
		}

		/* Can not host IPs on INACTIVE node */
		if (nodemap->node[i].flags & NODE_FLAGS_INACTIVE) {
			ipalloc_state->noiphost[i] = true;
		}
	}

	if (all_nodes_are_disabled(nodemap)) {
		/* If all nodes are disabled, can not host IPs on node
		 * with NoIPHostOnAllDisabled set
		 */
		for (i=0;i<nodemap->num;i++) {
			if (tval_noiphostonalldisabled[i] != 0) {
				ipalloc_state->noiphost[i] = true;
			}
		}
	} else {
		/* If some nodes are not disabled, then can not host
		 * IPs on DISABLED node
		 */
		for (i=0;i<nodemap->num;i++) {
			if (nodemap->node[i].flags & NODE_FLAGS_DISABLED) {
				ipalloc_state->noiphost[i] = true;
			}
		}
	}
}

void ipalloc_set_public_ips(struct ipalloc_state *ipalloc_state,
			    struct ctdb_public_ip_list *known_ips,
			    struct ctdb_public_ip_list *available_ips)
{
	ipalloc_state->available_public_ips = available_ips;
	ipalloc_state->known_public_ips = known_ips;
}

/* This can only return false if there are no available IPs *and*
 * there are no IP addresses currently allocated.  If the latter is
 * true then the cluster can clearly host IPs... just not necessarily
 * right now... */
bool ipalloc_can_host_ips(struct ipalloc_state *ipalloc_state)
{
	int i;
	bool have_ips = false;

	for (i=0; i < ipalloc_state->num; i++) {
		struct ctdb_public_ip_list *ips =
			ipalloc_state->known_public_ips;
		if (ips[i].num != 0) {
			int j;
			have_ips = true;
			/* Succeed if an address is hosted on node i */
			for (j=0; j < ips[i].num; j++) {
				if (ips[i].ip[j].pnn == i) {
					return true;
				}
			}
		}
	}

	if (! have_ips) {
		return false;
	}

	/* At this point there are known addresses but none are
	 * hosted.  Need to check if cluster can now host some
	 * addresses.
	 */
	for (i=0; i < ipalloc_state->num; i++) {
		if (ipalloc_state->available_public_ips[i].num != 0) {
			return true;
		}
	}

	return false;
}

/* The calculation part of the IP allocation algorithm. */
struct public_ip_list *ipalloc(struct ipalloc_state *ipalloc_state)
{
	bool ret = false;

	ipalloc_state->all_ips = create_merged_ip_list(ipalloc_state);
	if (ipalloc_state->all_ips == NULL) {
		return NULL;
	}

	switch (ipalloc_state->algorithm) {
	case IPALLOC_LCP2:
		ret = ipalloc_lcp2(ipalloc_state);
		break;
	case IPALLOC_DETERMINISTIC:
		ret = ipalloc_deterministic(ipalloc_state);
		break;
	case IPALLOC_NONDETERMINISTIC:
		ret = ipalloc_nondeterministic(ipalloc_state);
               break;
	}

	/* at this point ->pnn is the node which will own each IP
	   or -1 if there is no node that can cover this ip
	*/

	return (ret ? ipalloc_state->all_ips : NULL);
}

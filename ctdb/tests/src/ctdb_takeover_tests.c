/* 
   Tests for ctdb_takeover.c

   Copyright (C) Martin Schwenke 2011

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

#include <assert.h>
#include <talloc.h>

#include "replace.h"
#include "system/network.h"

#include "lib/util/debug.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "common/logging.h"
#include "common/system.h"

#include "server/ipalloc.h"

static void print_ctdb_public_ip_list(TALLOC_CTX *mem_ctx,
				      struct public_ip_list * ips)
{
	while (ips) {
		printf("%s %d\n",
		       ctdb_sock_addr_to_string(mem_ctx, &(ips->addr)),
		       ips->pnn);
		ips = ips->next;
	}
}

static uint32_t *get_tunable_values(TALLOC_CTX *tmp_ctx,
				    int numnodes,
				    const char *tunable);
static enum ctdb_runstate *get_runstate(TALLOC_CTX *tmp_ctx,
					int numnodes);

static void add_ip(TALLOC_CTX *mem_ctx,
		   struct ctdb_public_ip_list *l,
		   ctdb_sock_addr *addr,
		   uint32_t pnn)
{

	l->ip = talloc_realloc(mem_ctx, l->ip,
			       struct ctdb_public_ip, l->num + 1);
	assert(l->ip != NULL);

	l->ip[l->num].addr = *addr;
	l->ip[l->num].pnn  = pnn;
	l->num++;
}

/* Format of each line is "IP CURRENT_PNN [ALLOWED_PNN,...]".
 * If multi is true then ALLOWED_PNNs are not allowed.  */
static void read_ctdb_public_ip_info_node(int numnodes,
					  bool multi,
					  struct ctdb_public_ip_list **k,
					  struct ctdb_public_ip_list *known)
{
	char line[1024];
	ctdb_sock_addr addr;
	char *t, *tok;
	int pnn, n;

	/* Known public IPs */
	*k = talloc_zero(known, struct ctdb_public_ip_list);
	assert(k != NULL);

	while (fgets(line, sizeof(line), stdin) != NULL) {

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		/* Exit on an empty line */
		if (line[0] == '\0') {
			break;
		}

		/* Get the IP address */
		tok = strtok(line, " \t");
		if (tok == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " WARNING, bad line ignored :%s\n", line));
			continue;
		}

		if (!parse_ip(tok, NULL, 0, &addr)) {
			DEBUG(DEBUG_ERR, (__location__ " ERROR, bad address :%s\n", tok));
			continue;
		}

		/* Get the PNN */
		pnn = -1;
		tok = strtok(NULL, " \t");
		if (tok != NULL) {
			pnn = (int) strtol(tok, (char **) NULL, 10);
		}

		add_ip(*k, *k, &addr, pnn);

		tok = strtok(NULL, " \t#");
		if (tok == NULL) {
			continue;
		}

		/* Handle allowed nodes for addr */
		assert(multi == false);
		t = strtok(tok, ",");
		while (t != NULL) {
			n = (int) strtol(t, (char **) NULL, 10);
			add_ip(known, &known[n], &addr, pnn);
			t = strtok(NULL, ",");
		}
	}
}

static void read_ctdb_public_ip_info(TALLOC_CTX *ctx,
				     int numnodes,
				     bool multi,
				     struct ctdb_public_ip_list ** known,
				     struct ctdb_public_ip_list ** avail)
{
	int n;
	struct ctdb_public_ip_list * k;
	enum ctdb_runstate *runstate;

	*known = talloc_zero_array(ctx, struct ctdb_public_ip_list,
				   numnodes);
	assert(*known != NULL);
	*avail = talloc_zero_array(ctx, struct ctdb_public_ip_list,
				   numnodes);
	assert(*avail != NULL);

	if (multi) {
		for (n = 0; n < numnodes; n++) {
			read_ctdb_public_ip_info_node(numnodes, multi,
						      &k, *known);

			(*known)[n] = *k;
		}
	} else {
		read_ctdb_public_ip_info_node(numnodes, multi, &k, *known);

		/* Assign it to any nodes that don't have a list assigned */
		for (n = 0; n < numnodes; n++) {
			if ((*known)[n].num == 0) {
				(*known)[n] = *k;
			}
		}
	}

	runstate = get_runstate(ctx, numnodes);
	for (n = 0; n < numnodes; n++) {
		if (runstate[n] == CTDB_RUNSTATE_RUNNING) {
			(*avail)[n] = (*known)[n];
		}
	}
}

static uint32_t *get_tunable_values(TALLOC_CTX *tmp_ctx,
				    int numnodes,
				    const char *tunable)
{
	int i;
	char *tok;
	uint32_t *tvals = talloc_zero_array(tmp_ctx, uint32_t, numnodes);
	char *t = getenv(tunable);

	if (t) {
		if (strcmp(t, "1") == 0) {
			for (i=0; i<numnodes; i++) {
				tvals[i] = 1;
			}
		} else {
			tok = strtok(t, ",");
			i = 0;
			while (tok != NULL) {
				tvals[i] =
					(uint32_t) strtol(tok, NULL, 0);
				i++;
				tok = strtok(NULL, ",");
			}
			if (i != numnodes) {
				fprintf(stderr, "ERROR: Wrong number of values in %s\n", tunable);
				exit(1);
			}
		}
	}

	return tvals;
}

static enum ctdb_runstate *get_runstate(TALLOC_CTX *tmp_ctx,
					int numnodes)
{
	int i;
	uint32_t *tvals;
	enum ctdb_runstate *runstate =
		talloc_zero_array(tmp_ctx, enum ctdb_runstate, numnodes);
	char *t = getenv("CTDB_TEST_RUNSTATE");

	if (t == NULL) {
		for (i=0; i<numnodes; i++) {
			runstate[i] = CTDB_RUNSTATE_RUNNING;
		}
	} else {
		tvals = get_tunable_values(tmp_ctx, numnodes, "CTDB_TEST_RUNSTATE");
		for (i=0; i<numnodes; i++) {
			runstate[i] = (enum ctdb_runstate) tvals[i];
		}
		talloc_free(tvals);
	}

	return runstate;
}

/* Fake up enough CTDB state to be able to run the IP allocation
 * algorithm.  Usually this sets up some standard state, sets the node
 * states from the command-line and reads the current IP layout from
 * stdin.
 *
 * However, if read_ips_for_multiple_nodes is true then each node's
 * idea of the IP layout is read separately from stdin.  In this mode
 * is doesn't make much sense to use read_ctdb_public_ip_info's
 * optional ALLOWED_PNN,... list in the input, since each node is
 * being handled separately anyway.  IPs for each node are separated
 * by a blank line.  This mode is for testing weird behaviours where
 * the IP layouts differs across nodes and we want to improve
 * create_merged_ip_list(), so should only be used in tests of
 * ipalloc().  Yes, it is a hack...  :-)
 */
static void ctdb_test_init(TALLOC_CTX *mem_ctx,
			   const char nodestates[],
			   struct ipalloc_state **ipalloc_state,
			   bool read_ips_for_multiple_nodes)
{
	struct ctdb_public_ip_list *known;
	struct ctdb_public_ip_list *avail;
	char *tok, *ns, *t;
	struct ctdb_node_map *nodemap;
	uint32_t *tval_noiptakeover;
	uint32_t *tval_noiptakeoverondisabled;
	ctdb_sock_addr sa_zero = { .ip = { 0 } };
	enum ipalloc_algorithm algorithm;

	/* Avoid that const */
	ns = talloc_strdup(mem_ctx, nodestates);

	nodemap = talloc_zero(mem_ctx, struct ctdb_node_map);
	assert(nodemap != NULL);
	nodemap->num = 0;
	tok = strtok(ns, ",");
	while (tok != NULL) {
		uint32_t n = nodemap->num;
		nodemap->node = talloc_realloc(nodemap, nodemap->node,
					       struct ctdb_node_and_flags, n+1);
		nodemap->node[n].pnn = n;
		nodemap->node[n].flags = (uint32_t) strtol(tok, NULL, 0);
		nodemap->node[n].addr = sa_zero;
		nodemap->num++;
		tok = strtok(NULL, ",");
	}

	algorithm = IPALLOC_LCP2;
	if ((t = getenv("CTDB_IP_ALGORITHM"))) {
		if (strcmp(t, "lcp2") == 0) {
			algorithm = IPALLOC_LCP2;
		} else if (strcmp(t, "nondet") == 0) {
			algorithm = IPALLOC_NONDETERMINISTIC;
		} else if (strcmp(t, "det") == 0) {
			algorithm = IPALLOC_DETERMINISTIC;
		} else {
			DEBUG(DEBUG_ERR,
			      ("ERROR: unknown IP algorithm %s\n", t));
			exit(1);
		}
	}

	*ipalloc_state = ipalloc_state_init(mem_ctx, nodemap->num,
					    algorithm,
					    false, NULL);
	assert(*ipalloc_state != NULL);

	read_ctdb_public_ip_info(mem_ctx, nodemap->num,
				 read_ips_for_multiple_nodes,
				 &known, &avail);

	ipalloc_set_public_ips(*ipalloc_state, known, avail);

	tval_noiptakeover = get_tunable_values(mem_ctx, nodemap->num,
					       "CTDB_SET_NoIPTakeover");
	assert(tval_noiptakeover != NULL);
	tval_noiptakeoverondisabled =
		get_tunable_values(mem_ctx, nodemap->num,
				   "CTDB_SET_NoIPHostOnAllDisabled");
	assert(tval_noiptakeoverondisabled != NULL);

	ipalloc_set_node_flags(*ipalloc_state, nodemap,
			       tval_noiptakeover,
			       tval_noiptakeoverondisabled);
}

/* IP layout is read from stdin.  See comment for ctdb_test_init() for
 * explanation of read_ips_for_multiple_nodes.
 */
static void ctdb_test_ipalloc(const char nodestates[],
			      bool read_ips_for_multiple_nodes)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct ipalloc_state *ipalloc_state;

	ctdb_test_init(tmp_ctx, nodestates, &ipalloc_state,
		       read_ips_for_multiple_nodes);

	print_ctdb_public_ip_list(tmp_ctx, ipalloc(ipalloc_state));

	talloc_free(tmp_ctx);
}

static void usage(void)
{
	fprintf(stderr, "usage: ctdb_takeover_tests <op>\n");
	exit(1);
}

int main(int argc, const char *argv[])
{
	DEBUGLEVEL = DEBUG_DEBUG;
	if (getenv("CTDB_TEST_LOGLEVEL")) {
		DEBUGLEVEL = atoi(getenv("CTDB_TEST_LOGLEVEL"));
	}

	if (argc < 2) {
		usage();
	}

	if (argc == 3 &&
		   strcmp(argv[1], "ipalloc") == 0) {
		ctdb_test_ipalloc(argv[2], false);
	} else if (argc == 4 &&
		   strcmp(argv[1], "ipalloc") == 0 &&
		   strcmp(argv[3], "multi") == 0) {
		ctdb_test_ipalloc(argv[2], true);
	} else {
		usage();
	}

	return 0;
}

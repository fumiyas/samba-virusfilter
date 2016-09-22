/*
   ctdb database library: old client interface

   Copyright (C) Andrew Tridgell  2006

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

#ifndef _CTDB_CLIENT_H
#define _CTDB_CLIENT_H

#include "common/srvid.h"
#include "ctdb_protocol.h"

enum control_state {
	CTDB_CONTROL_WAIT,
	CTDB_CONTROL_DONE,
	CTDB_CONTROL_ERROR,
	CTDB_CONTROL_TIMEOUT
};

struct ctdb_client_control_state {
	struct ctdb_context *ctdb;
	uint32_t reqid;
	int32_t status;
	TDB_DATA outdata;
	enum control_state state;
	char *errormsg;
	struct ctdb_req_control_old *c;

	/* if we have a callback registered for the completion (or failure) of
	   this control
	   if a callback is used, it MUST talloc_free the cb_data passed to it
	*/
	struct {
		void (*fn)(struct ctdb_client_control_state *);
		void *private_data;
	} async;
};

struct tevent_context;
struct ctdb_db_context;

/*
  allocate a packet for use in client<->daemon communication
 */
struct ctdb_req_header *_ctdbd_allocate_pkt(struct ctdb_context *ctdb,
					    TALLOC_CTX *mem_ctx,
					    enum ctdb_operation operation,
					    size_t length, size_t slength,
					    const char *type);

#define ctdbd_allocate_pkt(ctdb, mem_ctx, operation, length, type) \
	(type *)_ctdbd_allocate_pkt(ctdb, mem_ctx, operation, length, \
				    sizeof(type), #type)

int ctdb_call_local(struct ctdb_db_context *ctdb_db, struct ctdb_call *call,
		    struct ctdb_ltdb_header *header, TALLOC_CTX *mem_ctx,
		    TDB_DATA *data, bool updatetdb);

void ctdb_request_message(struct ctdb_context *ctdb,
			  struct ctdb_req_header *hdr);

void ctdb_client_read_cb(uint8_t *data, size_t cnt, void *args);

int ctdb_socket_connect(struct ctdb_context *ctdb);

/*
  make a ctdb call. The associated ctdb call function will be called on the DMASTER
  for the given record
*/
struct ctdb_client_call_state *ctdb_call_send(struct ctdb_db_context *ctdb_db,
					      struct ctdb_call *call);
int ctdb_call_recv(struct ctdb_client_call_state *state,
		   struct ctdb_call *call);
int ctdb_call(struct ctdb_db_context *ctdb_db, struct ctdb_call *call);

/* setup a handler for ctdb messages */
typedef void (*ctdb_msg_fn_t)(struct ctdb_context *, uint64_t srvid,
			      TDB_DATA data, void *);

int ctdb_client_set_message_handler(struct ctdb_context *ctdb, uint64_t srvid,
				    srvid_handler_fn handler,
				    void *private_data);
int ctdb_client_remove_message_handler(struct ctdb_context *ctdb,
				       uint64_t srvid, void *private_data);
int ctdb_client_check_message_handlers(struct ctdb_context *ctdb,
				       uint64_t *ids, uint32_t num,
				       uint8_t *result);

/* send a ctdb message */
int ctdb_client_send_message(struct ctdb_context *ctdb, uint32_t pnn,
			     uint64_t srvid, TDB_DATA data);

/*
   Fetch a ctdb record from a remote node. Underneath this will force the
   dmaster for the record to be moved to the local node.
*/
struct ctdb_record_handle *ctdb_fetch_lock(struct ctdb_db_context *ctdb_db,
					   TALLOC_CTX *mem_ctx,
					   TDB_DATA key, TDB_DATA *data);

struct ctdb_record_handle *ctdb_fetch_readonly_lock(
					struct ctdb_db_context *ctdb_db,
					TALLOC_CTX *mem_ctx, TDB_DATA key,
					TDB_DATA *data, int read_only);

int ctdb_record_store(struct ctdb_record_handle *h, TDB_DATA data);

int ctdb_fetch(struct ctdb_db_context *ctdb_db, TALLOC_CTX *mem_ctx,
	       TDB_DATA key, TDB_DATA *data);

struct ctdb_client_control_state *ctdb_control_send(struct ctdb_context *ctdb,
						    uint32_t destnode,
						    uint64_t srvid,
						    uint32_t opcode,
						    uint32_t flags,
						    TDB_DATA data,
						    TALLOC_CTX *mem_ctx,
						    struct timeval *timeout,
						    char **errormsg);
int ctdb_control_recv(struct ctdb_context *ctdb,
		      struct ctdb_client_control_state *state,
		      TALLOC_CTX *mem_ctx, TDB_DATA *outdata,
		      int32_t *status, char **errormsg);
int ctdb_control(struct ctdb_context *ctdb, uint32_t destnode, uint64_t srvid,
		 uint32_t opcode, uint32_t flags, TDB_DATA data,
		 TALLOC_CTX *mem_ctx, TDB_DATA *outdata, int32_t *status,
		 struct timeval *timeout, char **errormsg);

int ctdb_ctrl_process_exists(struct ctdb_context *ctdb, uint32_t destnode,
			     pid_t pid);

int ctdb_ctrl_statistics(struct ctdb_context *ctdb, uint32_t destnode,
			 struct ctdb_statistics *status);
int ctdb_ctrl_dbstatistics(struct ctdb_context *ctdb, uint32_t destnode,
			   uint32_t dbid, TALLOC_CTX *mem_ctx,
			   struct ctdb_db_statistics_old **dbstat);

int ctdb_ctrl_shutdown(struct ctdb_context *ctdb, struct timeval timeout,
		       uint32_t destnode);

int ctdb_ctrl_getvnnmap(struct ctdb_context *ctdb, struct timeval timeout,
			uint32_t destnode, TALLOC_CTX *mem_ctx,
			struct ctdb_vnn_map **vnnmap);
int ctdb_ctrl_setvnnmap(struct ctdb_context *ctdb, struct timeval timeout,
			uint32_t destnode, TALLOC_CTX *mem_ctx,
			struct ctdb_vnn_map *vnnmap);

/*
  get the recovery mode of a remote node
 */
struct ctdb_client_control_state *ctdb_ctrl_getrecmode_send(
					struct ctdb_context *ctdb,
					TALLOC_CTX *mem_ctx,
					struct timeval timeout,
					uint32_t destnode);
int ctdb_ctrl_getrecmode_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			      struct ctdb_client_control_state *state,
			      uint32_t *recmode);
int ctdb_ctrl_getrecmode(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			 struct timeval timeout, uint32_t destnode,
			 uint32_t *recmode);

/*
  set the recovery mode of a remote node
 */
int ctdb_ctrl_setrecmode(struct ctdb_context *ctdb, struct timeval timeout,
			 uint32_t destnode, uint32_t recmode);

/*
  get the recovery master of a remote node
 */
struct ctdb_client_control_state *ctdb_ctrl_getrecmaster_send(
					struct ctdb_context *ctdb,
					TALLOC_CTX *mem_ctx,
					struct timeval timeout,
					uint32_t destnode);
int ctdb_ctrl_getrecmaster_recv(struct ctdb_context *ctdb,
				TALLOC_CTX *mem_ctx,
				struct ctdb_client_control_state *state,
				uint32_t *recmaster);
int ctdb_ctrl_getrecmaster(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			   struct timeval timeout, uint32_t destnode,
			   uint32_t *recmaster);

/*
  set the recovery master of a remote node
 */
int ctdb_ctrl_setrecmaster(struct ctdb_context *ctdb, struct timeval timeout,
			   uint32_t destnode, uint32_t recmaster);

int ctdb_ctrl_getdbmap(struct ctdb_context *ctdb, struct timeval timeout,
		       uint32_t destnode, TALLOC_CTX *mem_ctx,
		       struct ctdb_dbid_map_old **dbmap);

int ctdb_ctrl_getnodemap(struct ctdb_context *ctdb, struct timeval timeout,
			 uint32_t destnode, TALLOC_CTX *mem_ctx,
			 struct ctdb_node_map_old **nodemap);

int ctdb_ctrl_getnodesfile(struct ctdb_context *ctdb, struct timeval timeout,
			   uint32_t destnode, TALLOC_CTX *mem_ctx,
			   struct ctdb_node_map_old **nodemap);

int ctdb_ctrl_reload_nodes_file(struct ctdb_context *ctdb,
				struct timeval timeout, uint32_t destnode);

struct ctdb_client_control_state *ctdb_ctrl_pulldb_send(
					struct ctdb_context *ctdb,
					uint32_t destnode, uint32_t dbid,
					uint32_t lmaster, TALLOC_CTX *mem_ctx,
					struct timeval timeout);
int ctdb_ctrl_pulldb_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			  struct ctdb_client_control_state *state,
			  TDB_DATA *outdata);
int ctdb_ctrl_pulldb(struct ctdb_context *ctdb, uint32_t destnode,
		     uint32_t dbid, uint32_t lmaster, TALLOC_CTX *mem_ctx,
		     struct timeval timeout, TDB_DATA *outdata);

/*
  change dmaster for all keys in the database to the new value
 */
int ctdb_ctrl_setdmaster(struct ctdb_context *ctdb, struct timeval timeout,
			 uint32_t destnode, TALLOC_CTX *mem_ctx,
			 uint32_t dbid, uint32_t dmaster);

int ctdb_ctrl_ping(struct ctdb_context *ctdb, uint32_t destnode);

int ctdb_ctrl_get_runstate(struct ctdb_context *ctdb, struct timeval timeout,
			   uint32_t destnode, uint32_t *runstate);

int ctdb_ctrl_getdbpath(struct ctdb_context *ctdb, struct timeval timeout,
			uint32_t destnode, uint32_t dbid,
			TALLOC_CTX *mem_ctx, const char **path);
int ctdb_ctrl_getdbname(struct ctdb_context *ctdb, struct timeval timeout,
			uint32_t destnode, uint32_t dbid,
			TALLOC_CTX *mem_ctx, const char **name);
int ctdb_ctrl_getdbhealth(struct ctdb_context *ctdb, struct timeval timeout,
			  uint32_t destnode, uint32_t dbid,
			  TALLOC_CTX *mem_ctx, const char **reason);
int ctdb_ctrl_getdbseqnum(struct ctdb_context *ctdb, struct timeval timeout,
			  uint32_t destnode, uint32_t dbid, uint64_t *seqnum);

int ctdb_ctrl_createdb(struct ctdb_context *ctdb, struct timeval timeout,
		       uint32_t destnode, TALLOC_CTX *mem_ctx,
		       const char *name, bool persistent);

int ctdb_ctrl_get_debuglevel(struct ctdb_context *ctdb, uint32_t destnode,
			     int32_t *level);
int ctdb_ctrl_set_debuglevel(struct ctdb_context *ctdb, uint32_t destnode,
			     int32_t level);

uint32_t *ctdb_get_connected_nodes(struct ctdb_context *ctdb,
				   struct timeval timeout,
				   TALLOC_CTX *mem_ctx, uint32_t *num_nodes);

int ctdb_statistics_reset(struct ctdb_context *ctdb, uint32_t destnode);

/*
  attach to a ctdb database
*/
struct ctdb_db_context *ctdb_attach(struct ctdb_context *ctdb,
				    struct timeval timeout,
				    const char *name,
				    bool persistent,
				    uint32_t tdb_flags);

int ctdb_detach(struct ctdb_context *ctdb, uint32_t db_id);

/* a ctdb call function */
typedef int (*ctdb_fn_t)(struct ctdb_call_info *);

/*
  setup a ctdb call function
*/
int ctdb_set_call(struct ctdb_db_context *ctdb_db, ctdb_fn_t fn, uint32_t id);


typedef int (*ctdb_traverse_func)(TDB_DATA, TDB_DATA, void *);

int ctdb_traverse(struct ctdb_db_context *ctdb_db, ctdb_traverse_func fn,
		  void *private_data);

struct ctdb_dump_db_context {
	struct ctdb_context *ctdb;
	FILE *f;
	bool printemptyrecords;
	bool printdatasize;
	bool printlmaster;
	bool printhash;
	bool printrecordflags;
};

int ctdb_dumpdb_record(TDB_DATA key, TDB_DATA data, void *p);
int ctdb_dump_db(struct ctdb_db_context *ctdb_db,
		 struct ctdb_dump_db_context *ctx);

/*
  get the pid of a ctdb daemon
 */
int ctdb_ctrl_getpid(struct ctdb_context *ctdb, struct timeval timeout,
		     uint32_t destnode, uint32_t *pid);

int ctdb_ctrl_freeze(struct ctdb_context *ctdb, struct timeval timeout,
		     uint32_t destnode);

int ctdb_ctrl_getpnn(struct ctdb_context *ctdb, struct timeval timeout,
		     uint32_t destnode);

/*
  get the monitoring mode of a remote node
 */
int ctdb_ctrl_getmonmode(struct ctdb_context *ctdb, struct timeval timeout,
			 uint32_t destnode, uint32_t *monmode);

/*
  set the monitoring mode of a remote node to active
 */
int ctdb_ctrl_enable_monmode(struct ctdb_context *ctdb,
			     struct timeval timeout, uint32_t destnode);

/*
  set the monitoring mode of a remote node to disabled
 */
int ctdb_ctrl_disable_monmode(struct ctdb_context *ctdb,
			      struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_takeover_ip(struct ctdb_context *ctdb, struct timeval timeout,
			  uint32_t destnode, struct ctdb_public_ip *ip);
int ctdb_ctrl_release_ip(struct ctdb_context *ctdb, struct timeval timeout,
			 uint32_t destnode, struct ctdb_public_ip *ip);

int ctdb_ctrl_get_tunable(struct ctdb_context *ctdb,
			  struct timeval timeout, uint32_t destnode,
			  const char *name, uint32_t *value);
int ctdb_ctrl_set_tunable(struct ctdb_context *ctdb,
			  struct timeval timeout, uint32_t destnode,
			  const char *name, uint32_t value);
int ctdb_ctrl_list_tunables(struct ctdb_context *ctdb,
			    struct timeval timeout, uint32_t destnode,
			    TALLOC_CTX *mem_ctx,
			    const char ***list, uint32_t *count);

int ctdb_ctrl_get_public_ips_flags(struct ctdb_context *ctdb,
				   struct timeval timeout, uint32_t destnode,
				   TALLOC_CTX *mem_ctx, uint32_t flags,
				   struct ctdb_public_ip_list_old **ips);
int ctdb_ctrl_get_public_ips(struct ctdb_context *ctdb,
			     struct timeval timeout, uint32_t destnode,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_list_old **ips);
int ctdb_ctrl_get_public_ip_info(struct ctdb_context *ctdb,
				 struct timeval timeout, uint32_t destnode,
				 TALLOC_CTX *mem_ctx,
				 const ctdb_sock_addr *addr,
				 struct ctdb_public_ip_info_old **info);

int ctdb_ctrl_get_ifaces(struct ctdb_context *ctdb,
			 struct timeval timeout, uint32_t destnode,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_iface_list_old **ifaces);
int ctdb_ctrl_set_iface_link(struct ctdb_context *ctdb,
			     struct timeval timeout, uint32_t destnode,
			     TALLOC_CTX *mem_ctx,
			     const struct ctdb_iface *info);

int ctdb_ctrl_modflags(struct ctdb_context *ctdb,
		       struct timeval timeout,
		       uint32_t destnode,
		       uint32_t set, uint32_t clear);

int ctdb_ctrl_get_all_tunables(struct ctdb_context *ctdb,
			       struct timeval timeout, uint32_t destnode,
			       struct ctdb_tunable_list *tunables);

int ctdb_ctrl_add_public_ip(struct ctdb_context *ctdb,
			    struct timeval timeout, uint32_t destnode,
			    struct ctdb_addr_info_old *pub);
int ctdb_ctrl_del_public_ip(struct ctdb_context *ctdb,
			    struct timeval timeout, uint32_t destnode,
			    struct ctdb_addr_info_old *pub);

int ctdb_ctrl_gratious_arp(struct ctdb_context *ctdb,
			   struct timeval timeout, uint32_t destnode,
			   ctdb_sock_addr *addr, const char *ifname);

int ctdb_ctrl_get_tcp_tickles(struct ctdb_context *ctdb,
			      struct timeval timeout, uint32_t destnode,
			      TALLOC_CTX *mem_ctx, ctdb_sock_addr *addr,
			      struct ctdb_tickle_list_old **list);

/*
  initialise ctdb subsystem
*/
struct ctdb_context *ctdb_init(struct tevent_context *ev);

/*
  set some flags
*/
void ctdb_set_flags(struct ctdb_context *ctdb, unsigned flags);

int ctdb_set_socketname(struct ctdb_context *ctdb, const char *socketname);
const char *ctdb_get_socketname(struct ctdb_context *ctdb);

/* return pnn of this node */
uint32_t ctdb_get_pnn(struct ctdb_context *ctdb);

/*
  get the uptime of a remote node
 */
struct ctdb_client_control_state *ctdb_ctrl_uptime_send(
					struct ctdb_context *ctdb,
					TALLOC_CTX *mem_ctx,
					struct timeval timeout,
					uint32_t destnode);
int ctdb_ctrl_uptime_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			  struct ctdb_client_control_state *state,
			  struct ctdb_uptime **uptime);
int ctdb_ctrl_uptime(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
		     struct timeval timeout, uint32_t destnode,
		     struct ctdb_uptime **uptime);

int ctdb_ctrl_end_recovery(struct ctdb_context *ctdb, struct timeval timeout,
			   uint32_t destnode);

typedef void (*client_async_callback)(struct ctdb_context *ctdb,
				      uint32_t node_pnn, int32_t res,
				      TDB_DATA outdata, void *callback_data);

struct client_async_data {
	enum ctdb_controls opcode;
	bool dont_log_errors;
	uint32_t count;
	uint32_t fail_count;
	client_async_callback callback;
	client_async_callback fail_callback;
	void *callback_data;
};

void ctdb_client_async_add(struct client_async_data *data,
			   struct ctdb_client_control_state *state);
int ctdb_client_async_wait(struct ctdb_context *ctdb,
			   struct client_async_data *data);
int ctdb_client_async_control(struct ctdb_context *ctdb,
			      enum ctdb_controls opcode, uint32_t *nodes,
			      uint64_t srvid, struct timeval timeout,
			      bool dont_log_errors, TDB_DATA data,
			      client_async_callback client_callback,
			      client_async_callback fail_callback,
			      void *callback_data);

uint32_t *list_of_vnnmap_nodes(struct ctdb_context *ctdb,
			       struct ctdb_vnn_map *vnn_map,
			       TALLOC_CTX *mem_ctx, bool include_self);

uint32_t *list_of_nodes(struct ctdb_context *ctdb,
			struct ctdb_node_map_old *node_map,
			TALLOC_CTX *mem_ctx, uint32_t mask, int exclude_pnn);
uint32_t *list_of_active_nodes(struct ctdb_context *ctdb,
			       struct ctdb_node_map_old *node_map,
			       TALLOC_CTX *mem_ctx, bool include_self);
uint32_t *list_of_connected_nodes(struct ctdb_context *ctdb,
				  struct ctdb_node_map_old *node_map,
				  TALLOC_CTX *mem_ctx, bool include_self);

int ctdb_read_pnn_lock(int fd, int32_t pnn);

/*
  get capabilities of a remote node
 */

struct ctdb_client_control_state *ctdb_ctrl_getcapabilities_send(
					struct ctdb_context *ctdb,
					TALLOC_CTX *mem_ctx,
					struct timeval timeout,
					uint32_t destnode);
int ctdb_ctrl_getcapabilities_recv(struct ctdb_context *ctdb,
				   TALLOC_CTX *mem_ctx,
				   struct ctdb_client_control_state *state,
				   uint32_t *capabilities);
int ctdb_ctrl_getcapabilities(struct ctdb_context *ctdb,
			      struct timeval timeout, uint32_t destnode,
			      uint32_t *capabilities);

struct ctdb_node_capabilities {
	bool retrieved;
	uint32_t capabilities;
};

/* Retrieve capabilities for all connected nodes.  The length of the
 * returned array can be calculated using talloc_array_length(). */
struct ctdb_node_capabilities *ctdb_get_capabilities(
					struct ctdb_context *ctdb,
					TALLOC_CTX *mem_ctx,
					struct timeval timeout,
					struct ctdb_node_map_old *nodemap);

/* Get capabilities for specified node, NULL if not found */
uint32_t *ctdb_get_node_capabilities(struct ctdb_node_capabilities *caps,
				     uint32_t pnn);

/* True if the given node has all of the required capabilities */
bool ctdb_node_has_capabilities(struct ctdb_node_capabilities *caps,
				uint32_t pnn, uint32_t capabilities_required);


struct ctdb_transaction_handle *ctdb_transaction_start(
					struct ctdb_db_context *ctdb_db,
					TALLOC_CTX *mem_ctx);
int ctdb_transaction_fetch(struct ctdb_transaction_handle *h,
			   TALLOC_CTX *mem_ctx,
			   TDB_DATA key, TDB_DATA *data);
int ctdb_transaction_store(struct ctdb_transaction_handle *h,
			   TDB_DATA key, TDB_DATA data);
int ctdb_transaction_commit(struct ctdb_transaction_handle *h);
int ctdb_transaction_cancel(struct ctdb_transaction_handle *h);

int ctdb_ctrl_recd_ping(struct ctdb_context *ctdb);

int ctdb_ctrl_getscriptstatus(struct ctdb_context *ctdb,
			      struct timeval timeout, uint32_t destnode,
			      TALLOC_CTX *mem_ctx,
			      enum ctdb_event type,
			      struct ctdb_script_list_old **script_status);

int ctdb_ctrl_report_recd_lock_latency(struct ctdb_context *ctdb,
				       struct timeval timeout, double latency);

int ctdb_ctrl_getreclock(struct ctdb_context *ctdb,
			 struct timeval timeout, uint32_t destnode,
			 TALLOC_CTX *mem_ctx, const char **reclock);

int ctdb_ctrl_stop_node(struct ctdb_context *ctdb, struct timeval timeout,
			uint32_t destnode);
int ctdb_ctrl_continue_node(struct ctdb_context *ctdb, struct timeval timeout,
			    uint32_t destnode);

int ctdb_ctrl_setlmasterrole(struct ctdb_context *ctdb,
			     struct timeval timeout, uint32_t destnode,
			     uint32_t lmasterrole);
int ctdb_ctrl_setrecmasterrole(struct ctdb_context *ctdb,
			       struct timeval timeout, uint32_t destnode,
			       uint32_t recmasterrole);

int ctdb_ctrl_enablescript(struct ctdb_context *ctdb, struct timeval timeout,
			   uint32_t destnode, const char *script);
int ctdb_ctrl_disablescript(struct ctdb_context *ctdb, struct timeval timeout,
			    uint32_t destnode, const char *script);

int ctdb_ctrl_set_ban(struct ctdb_context *ctdb, struct timeval timeout,
		      uint32_t destnode, struct ctdb_ban_state *bantime);
int ctdb_ctrl_get_ban(struct ctdb_context *ctdb, struct timeval timeout,
		      uint32_t destnode, TALLOC_CTX *mem_ctx,
		      struct ctdb_ban_state **bantime);

int ctdb_ctrl_getstathistory(struct ctdb_context *ctdb,
			     struct timeval timeout, uint32_t destnode,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_statistics_list_old **stats);

struct ctdb_ltdb_header *ctdb_header_from_record_handle(
					struct ctdb_record_handle *h);

struct ctdb_client_control_state *ctdb_ctrl_updaterecord_send(
					struct ctdb_context *ctdb,
					TALLOC_CTX *mem_ctx,
					struct timeval timeout,
					uint32_t destnode,
					struct ctdb_db_context *ctdb_db,
					TDB_DATA key,
					struct ctdb_ltdb_header *header,
					TDB_DATA data);
int ctdb_ctrl_updaterecord_recv(struct ctdb_context *ctdb,
				struct ctdb_client_control_state *state);
int ctdb_ctrl_updaterecord(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			   struct timeval timeout, uint32_t destnode,
			   struct ctdb_db_context *ctdb_db, TDB_DATA key,
			   struct ctdb_ltdb_header *header, TDB_DATA data);

struct ctdb_client_control_state *ctdb_ctrl_set_db_readonly_send(
					struct ctdb_context *ctdb,
					uint32_t destnode, uint32_t dbid);
int ctdb_ctrl_set_db_readonly_recv(struct ctdb_context *ctdb,
				   struct ctdb_client_control_state *state);
int ctdb_ctrl_set_db_readonly(struct ctdb_context *ctdb, uint32_t destnode,
			      uint32_t dbid);

struct ctdb_client_control_state *ctdb_ctrl_set_db_sticky_send(
					struct ctdb_context *ctdb,
					uint32_t destnode, uint32_t dbid);
int ctdb_ctrl_set_db_sticky_recv(struct ctdb_context *ctdb,
				 struct ctdb_client_control_state *state);
int ctdb_ctrl_set_db_sticky(struct ctdb_context *ctdb, uint32_t destnode,
			    uint32_t dbid);

#endif /* _CTDB_CLIENT_H */

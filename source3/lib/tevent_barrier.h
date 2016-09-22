/*
   Unix SMB/CIFS implementation.
   Implement a barrier
   Copyright (C) Volker Lendecke 2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _TEVENT_BARRIER_H
#define _TEVENT_BARRIER_H

#include "talloc.h"
#include "tevent.h"

struct tevent_barrier;

struct tevent_barrier *tevent_barrier_init(
	TALLOC_CTX *mem_ctx, unsigned count,
	void (*trigger_cb)(void *private_data), void *private_data);

struct tevent_req *tevent_barrier_wait_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tevent_barrier *b);
int tevent_barrier_wait_recv(struct tevent_req *req);

#endif /* _TEVENT_BARRIER_H */

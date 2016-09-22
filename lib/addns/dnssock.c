/*
  Linux DNS client library implementation

  Copyright (C) 2006 Krishna Ganugapati <krishnag@centeris.com>
  Copyright (C) 2006 Gerald Carter <jerry@samba.org>

     ** NOTE! The following LGPL license applies to the libaddns
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "dns.h"
#include <sys/time.h>
#include <unistd.h>
#include "system/select.h"
#include "../lib/util/debug.h"

static int destroy_dns_connection(struct dns_connection *conn)
{
	return close(conn->s);
}

/********************************************************************
********************************************************************/

static DNS_ERROR dns_open_helper(const char *nameserver,
				 const char *service,
				 struct addrinfo *hints,
				 TALLOC_CTX *mem_ctx,
				 struct dns_connection **ret_conn)
{
	int ret;
	struct addrinfo *rp;
	struct addrinfo *ai_result = NULL;
	struct dns_connection *conn = NULL;

	if (!(conn = talloc(mem_ctx, struct dns_connection))) {
		return ERROR_DNS_NO_MEMORY;
	}

	ret = getaddrinfo(nameserver, service, hints, &ai_result);
	if (ret != 0) {
		DEBUG(1,("dns_tcp_open: getaddrinfo: %s\n", gai_strerror(ret)));
		TALLOC_FREE(conn);
		return ERROR_DNS_INVALID_NAME_SERVER;
	}

	for (rp = ai_result; rp != NULL; rp = rp->ai_next) {
		conn->s = socket(rp->ai_family,
				rp->ai_socktype,
				rp->ai_protocol);
		if (conn->s == -1) {
			continue;
		}
		do {
			ret = connect(conn->s, rp->ai_addr, rp->ai_addrlen);
		} while ((ret == -1) && (errno == EINTR));
		if (ret != -1) {
			/* Successful connect */
			break;
		}
		close(conn->s);
	}

	freeaddrinfo(ai_result);

	if (rp == NULL) {
		TALLOC_FREE(conn);
		return ERROR_DNS_CONNECTION_FAILED;
	}

	talloc_set_destructor(conn, destroy_dns_connection);

	*ret_conn = conn;
	return ERROR_DNS_SUCCESS;
}

static DNS_ERROR dns_tcp_open( const char *nameserver,
			       TALLOC_CTX *mem_ctx,
			       struct dns_connection **result )
{
	struct addrinfo hints;
	struct dns_connection *conn;
	DNS_ERROR dns_ret;
	char service[16];

	snprintf(service, sizeof(service), "%d", DNS_TCP_PORT);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = IPPROTO_TCP;

	dns_ret = dns_open_helper(nameserver, service, &hints, mem_ctx, &conn);
	if (!ERR_DNS_IS_OK(dns_ret)) {
		return dns_ret;
	}

	conn->hType = DNS_TCP;
	*result = conn;
	return ERROR_DNS_SUCCESS;
}

/********************************************************************
 * ********************************************************************/

static DNS_ERROR dns_udp_open( const char *nameserver,
			       TALLOC_CTX *mem_ctx,
			       struct dns_connection **result )
{
	struct addrinfo hints;
	struct sockaddr_storage RecvAddr;
	struct dns_connection *conn;
	DNS_ERROR dns_ret;
	socklen_t RecvAddrLen;
	char service[16];

	snprintf(service, sizeof(service), "%d", DNS_UDP_PORT);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = IPPROTO_UDP;

	dns_ret = dns_open_helper(nameserver, service, &hints, mem_ctx, &conn);
	if (!ERR_DNS_IS_OK(dns_ret)) {
		TALLOC_FREE(conn);
		return dns_ret;
	}

	/* Set up the RecvAddr structure with the IP address of
	   the receiver and the specified port number. */

	RecvAddrLen = sizeof(RecvAddr);
	if (getpeername(conn->s,
			(struct sockaddr *)&RecvAddr,
			&RecvAddrLen) == -1) {
		return ERROR_DNS_CONNECTION_FAILED;
	}

	conn->hType = DNS_UDP;
	memcpy(&conn->RecvAddr, &RecvAddr, sizeof(struct sockaddr_storage));

	*result = conn;
	return ERROR_DNS_SUCCESS;
}

/********************************************************************
********************************************************************/

DNS_ERROR dns_open_connection( const char *nameserver, int32_t dwType,
		    TALLOC_CTX *mem_ctx,
		    struct dns_connection **conn )
{
	switch ( dwType ) {
	case DNS_TCP:
		return dns_tcp_open( nameserver, mem_ctx, conn );
	case DNS_UDP:
		return dns_udp_open( nameserver, mem_ctx, conn );
	}

	return ERROR_DNS_INVALID_PARAMETER;
}

static DNS_ERROR write_all(int fd, uint8_t *data, size_t len)
{
	size_t total = 0;

	while (total < len) {

		ssize_t ret;

		do {
			ret = write(fd, data + total, len - total);
		} while ((ret == -1) && (errno == EINTR));

		if (ret <= 0) {
			/*
			 * EOF or error
			 */
			return ERROR_DNS_SOCKET_ERROR;
		}

		total += ret;
	}

	return ERROR_DNS_SUCCESS;
}

static DNS_ERROR dns_send_tcp(struct dns_connection *conn,
			      const struct dns_buffer *buf)
{
	uint16_t len = htons(buf->offset);
	DNS_ERROR err;

	err = write_all(conn->s, (uint8_t *)&len, sizeof(len));
	if (!ERR_DNS_IS_OK(err)) return err;

	return write_all(conn->s, buf->data, buf->offset);
}

static DNS_ERROR dns_send_udp(struct dns_connection *conn,
			      const struct dns_buffer *buf)
{
	ssize_t ret;

	do {
		ret = sendto(conn->s, buf->data, buf->offset, 0,
		     (struct sockaddr *)&conn->RecvAddr,
		     sizeof(conn->RecvAddr));
	} while ((ret == -1) && (errno == EINTR));

	if (ret != buf->offset) {
		return ERROR_DNS_SOCKET_ERROR;
	}

	return ERROR_DNS_SUCCESS;
}

DNS_ERROR dns_send(struct dns_connection *conn, const struct dns_buffer *buf)
{
	if (conn->hType == DNS_TCP) {
		return dns_send_tcp(conn, buf);
	}

	if (conn->hType == DNS_UDP) {
		return dns_send_udp(conn, buf);
	}

	return ERROR_DNS_INVALID_PARAMETER;
}

static DNS_ERROR read_all(int fd, uint8_t *data, size_t len)
{
	size_t total = 0;

	while (total < len) {
		struct pollfd pfd;
		ssize_t ret;
		int fd_ready;

		ZERO_STRUCT(pfd);
		pfd.fd = fd;
		pfd.events = POLLIN|POLLHUP;

		fd_ready = poll(&pfd, 1, 10000);
		if (fd_ready == -1) {
			if (errno == EINTR) {
				continue;
			}
			return ERROR_DNS_SOCKET_ERROR;
		}
		if ( fd_ready == 0 ) {
			/* read timeout */
			return ERROR_DNS_SOCKET_ERROR;
		}

		do {
			ret = read(fd, data + total, len - total);
		} while ((ret == -1) && (errno == EINTR));

		if (ret <= 0) {
			/* EOF or error */
			return ERROR_DNS_SOCKET_ERROR;
		}

		total += ret;
	}

	return ERROR_DNS_SUCCESS;
}

static DNS_ERROR dns_receive_tcp(TALLOC_CTX *mem_ctx,
				 struct dns_connection *conn,
				 struct dns_buffer **presult)
{
	struct dns_buffer *buf;
	DNS_ERROR err;
	uint16_t len;

	if (!(buf = talloc_zero(mem_ctx, struct dns_buffer))) {
		return ERROR_DNS_NO_MEMORY;
	}

	err = read_all(conn->s, (uint8_t *)&len, sizeof(len));
	if (!ERR_DNS_IS_OK(err)) {
		return err;
	}

	buf->size = ntohs(len);

	if (buf->size == 0) {
		*presult = buf;
		return ERROR_DNS_SUCCESS;
	}

	if (!(buf->data = talloc_array(buf, uint8_t, buf->size))) {
		TALLOC_FREE(buf);
		return ERROR_DNS_NO_MEMORY;
	}

	err = read_all(conn->s, buf->data, talloc_get_size(buf->data));
	if (!ERR_DNS_IS_OK(err)) {
		TALLOC_FREE(buf);
		return err;
	}

	*presult = buf;
	return ERROR_DNS_SUCCESS;
}

static DNS_ERROR dns_receive_udp(TALLOC_CTX *mem_ctx,
				 struct dns_connection *conn,
				 struct dns_buffer **presult)
{
	struct dns_buffer *buf;
	ssize_t received;

	if (!(buf = talloc_zero(mem_ctx, struct dns_buffer))) {
		return ERROR_DNS_NO_MEMORY;
	}

	/*
	 * UDP based DNS can only be 512 bytes
	 */

	if (!(buf->data = talloc_array(buf, uint8_t, 512))) {
		TALLOC_FREE(buf);
		return ERROR_DNS_NO_MEMORY;
	}

	do {
		received = recv(conn->s, (void *)buf->data, 512, 0);
	} while ((received == -1) && (errno == EINTR));

	if (received == -1) {
		TALLOC_FREE(buf);
		return ERROR_DNS_SOCKET_ERROR;
	}

	if (received > 512) {
		TALLOC_FREE(buf);
		return ERROR_DNS_BAD_RESPONSE;
	}

	buf->size = received;
	buf->offset = 0;

	*presult = buf;
	return ERROR_DNS_SUCCESS;
}

DNS_ERROR dns_receive(TALLOC_CTX *mem_ctx, struct dns_connection *conn,
		      struct dns_buffer **presult)
{
	if (conn->hType == DNS_TCP) {
		return dns_receive_tcp(mem_ctx, conn, presult);
	}

	if (conn->hType == DNS_UDP) {
		return dns_receive_udp(mem_ctx, conn, presult);
	}

	return ERROR_DNS_INVALID_PARAMETER;
}

DNS_ERROR dns_transaction(TALLOC_CTX *mem_ctx, struct dns_connection *conn,
			  const struct dns_request *req,
			  struct dns_request **resp)
{
	struct dns_buffer *buf = NULL;
	DNS_ERROR err;

	err = dns_marshall_request(mem_ctx, req, &buf);
	if (!ERR_DNS_IS_OK(err)) goto error;

	err = dns_send(conn, buf);
	if (!ERR_DNS_IS_OK(err)) goto error;
	TALLOC_FREE(buf);

	err = dns_receive(mem_ctx, conn, &buf);
	if (!ERR_DNS_IS_OK(err)) goto error;

	err = dns_unmarshall_request(mem_ctx, buf, resp);

 error:
	TALLOC_FREE(buf);
	return err;
}

DNS_ERROR dns_update_transaction(TALLOC_CTX *mem_ctx,
				 struct dns_connection *conn,
				 struct dns_update_request *up_req,
				 struct dns_update_request **up_resp)
{
	struct dns_request *resp;
	DNS_ERROR err;

	err = dns_transaction(mem_ctx, conn, dns_update2request(up_req),
			      &resp);

	if (!ERR_DNS_IS_OK(err)) return err;

	*up_resp = dns_request2update(resp);
	return ERROR_DNS_SUCCESS;
}

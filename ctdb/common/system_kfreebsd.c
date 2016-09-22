/* 
   ctdb system specific code to manage raw sockets on linux

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Marc Dequènes (Duck) 2009

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


  This file is a copy of 'common/system_linux.c' adapted for Hurd^W kFreeBSD
  needs, and inspired by 'common/system_aix.c' for the pcap usage.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"

#include "lib/util/debug.h"
#include "lib/util/blocking.h"

#include "protocol/protocol.h"

#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <pcap.h>

#include "common/logging.h"
#include "common/system.h"

#ifndef ETHERTYPE_IP6
#define ETHERTYPE_IP6 0x86dd
#endif

/*
  calculate the tcp checksum for tcp over ipv6
*/
static uint16_t tcp_checksum6(uint16_t *data, size_t n, struct ip6_hdr *ip6)
{
	uint32_t phdr[2];
	uint32_t sum = 0;
	uint16_t sum2;

	sum += uint16_checksum((uint16_t *)(void *)&ip6->ip6_src, 16);
	sum += uint16_checksum((uint16_t *)(void *)&ip6->ip6_dst, 16);

	phdr[0] = htonl(n);
	phdr[1] = htonl(ip6->ip6_nxt);
	sum += uint16_checksum((uint16_t *)phdr, 8);

	sum += uint16_checksum(data, n);

	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum2 = htons(sum);
	sum2 = ~sum2;
	if (sum2 == 0) {
		return 0xFFFF;
	}
	return sum2;
}

/*
  send gratuitous arp reply after we have taken over an ip address

  saddr is the address we are trying to claim
  iface is the interface name we will be using to claim the address
 */
int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface)
{
	/* FIXME kFreeBSD: We don't do gratuitous arp yet */
	return -1;
}


/*
  simple TCP checksum - assumes data is multiple of 2 bytes long
 */
static uint16_t tcp_checksum(uint16_t *data, size_t n, struct iphdr *ip)
{
	uint32_t sum = uint16_checksum(data, n);
	uint16_t sum2;
	sum += uint16_checksum((uint16_t *)(void *)&ip->saddr,
			       sizeof(ip->saddr));
	sum += uint16_checksum((uint16_t *)(void *)&ip->daddr,
			       sizeof(ip->daddr));
	sum += ip->protocol + n;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum2 = htons(sum);
	sum2 = ~sum2;
	if (sum2 == 0) {
		return 0xFFFF;
	}
	return sum2;
}

/*
  Send tcp segment from the specified IP/port to the specified
  destination IP/port. 

  This is used to trigger the receiving host into sending its own ACK,
  which should trigger early detection of TCP reset by the client
  after IP takeover

  This can also be used to send RST segments (if rst is true) and also
  if correct seq and ack numbers are provided.
 */
int ctdb_sys_send_tcp(const ctdb_sock_addr *dest, 
		      const ctdb_sock_addr *src,
		      uint32_t seq, uint32_t ack, int rst)
{
	int s;
	int ret;
	uint32_t one = 1;
	uint16_t tmpport;
	ctdb_sock_addr *tmpdest;
	struct {
		struct iphdr ip;
		struct tcphdr tcp;
	} ip4pkt;
	struct {
		struct ip6_hdr ip6;
		struct tcphdr tcp;
	} ip6pkt;
	int saved_errno;

	switch (src->ip.sin_family) {
	case AF_INET:
		ZERO_STRUCT(ip4pkt);
		ip4pkt.ip.version  = 4;
		ip4pkt.ip.ihl      = sizeof(ip4pkt.ip)/4;
		ip4pkt.ip.tot_len  = htons(sizeof(ip4pkt));
		ip4pkt.ip.ttl      = 255;
		ip4pkt.ip.protocol = IPPROTO_TCP;
		ip4pkt.ip.saddr    = src->ip.sin_addr.s_addr;
		ip4pkt.ip.daddr    = dest->ip.sin_addr.s_addr;
		ip4pkt.ip.check    = 0;

		ip4pkt.tcp.source   = src->ip.sin_port;
		ip4pkt.tcp.dest     = dest->ip.sin_port;
		ip4pkt.tcp.seq      = seq;
		ip4pkt.tcp.ack_seq  = ack;
		ip4pkt.tcp.ack      = 1;
		if (rst) {
			ip4pkt.tcp.rst      = 1;
		}
		ip4pkt.tcp.doff     = sizeof(ip4pkt.tcp)/4;
		/* this makes it easier to spot in a sniffer */
		ip4pkt.tcp.window   = htons(1234);
		ip4pkt.tcp.check    = tcp_checksum((uint16_t *)&ip4pkt.tcp, sizeof(ip4pkt.tcp), &ip4pkt.ip);

		/* open a raw socket to send this segment from */
		s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (s == -1) {
			DEBUG(DEBUG_CRIT,(__location__ " failed to open raw socket (%s)\n",
				 strerror(errno)));
			return -1;
		}

		ret = setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
		if (ret != 0) {
			DEBUG(DEBUG_CRIT,(__location__ " failed to setup IP headers (%s)\n",
				 strerror(errno)));
			close(s);
			return -1;
		}

		ret = sendto(s, &ip4pkt, sizeof(ip4pkt), 0,
			     &dest->ip, sizeof(dest->ip));
		saved_errno = errno;
		close(s);
		if (ret != sizeof(ip4pkt)) {
			DEBUG(DEBUG_ERR,
			      ("Failed sendto (%s)\n", strerror(saved_errno)));
			return -1;
		}
		break;
	case AF_INET6:
		ZERO_STRUCT(ip6pkt);
		ip6pkt.ip6.ip6_vfc  = 0x60;
		ip6pkt.ip6.ip6_plen = htons(20);
		ip6pkt.ip6.ip6_nxt  = IPPROTO_TCP;
		ip6pkt.ip6.ip6_hlim = 64;
		ip6pkt.ip6.ip6_src  = src->ip6.sin6_addr;
		ip6pkt.ip6.ip6_dst  = dest->ip6.sin6_addr;

		ip6pkt.tcp.source   = src->ip6.sin6_port;
		ip6pkt.tcp.dest     = dest->ip6.sin6_port;
		ip6pkt.tcp.seq      = seq;
		ip6pkt.tcp.ack_seq  = ack;
		ip6pkt.tcp.ack      = 1;
		if (rst) {
			ip6pkt.tcp.rst      = 1;
		}
		ip6pkt.tcp.doff     = sizeof(ip6pkt.tcp)/4;
		/* this makes it easier to spot in a sniffer */
		ip6pkt.tcp.window   = htons(1234);
		ip6pkt.tcp.check    = tcp_checksum6((uint16_t *)&ip6pkt.tcp, sizeof(ip6pkt.tcp), &ip6pkt.ip6);

		s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
		if (s == -1) {
			DEBUG(DEBUG_CRIT, (__location__ " Failed to open sending socket\n"));
			return -1;

		}
		/* sendto() don't like if the port is set and the socket is
		   in raw mode.
		*/
		tmpdest = discard_const(dest);
		tmpport = tmpdest->ip6.sin6_port;

		tmpdest->ip6.sin6_port = 0;
		ret = sendto(s, &ip6pkt, sizeof(ip6pkt), 0,
			     &dest->ip6, sizeof(dest->ip6));
		saved_errno = errno;
		tmpdest->ip6.sin6_port = tmpport;
		close(s);

		if (ret != sizeof(ip6pkt)) {
			DEBUG(DEBUG_ERR,
			      ("Failed sendto (%s)\n", strerror(saved_errno)));
			return -1;
		}
		break;

	default:
		DEBUG(DEBUG_CRIT,(__location__ " not an ipv4/v6 address\n"));
		return -1;
	}

	return 0;
}

/* 
   This function is used to open a raw socket to capture from
 */
int ctdb_sys_open_capture_socket(const char *iface, void **private_data)
{
	pcap_t *pt;

	pt=pcap_open_live(iface, 100, 0, 0, NULL);
	if (pt == NULL) {
		DEBUG(DEBUG_CRIT,("Failed to open capture device %s\n", iface));
		return -1;
	}
	*((pcap_t **)private_data) = pt;

	return pcap_fileno(pt);
}

/* This function is used to close the capture socket
 */
int ctdb_sys_close_capture_socket(void *private_data)
{
	pcap_t *pt = (pcap_t *)private_data;
	pcap_close(pt);
	return 0;
}


/*
  called when the raw socket becomes readable
 */
int ctdb_sys_read_tcp_packet(int s, void *private_data,
			     ctdb_sock_addr *src, ctdb_sock_addr *dst,
			     uint32_t *ack_seq, uint32_t *seq,
			     int *rst, uint16_t *window)
{
	int ret;
#define RCVPKTSIZE 100
	char pkt[RCVPKTSIZE];
	struct ether_header *eth;
	struct iphdr *ip;
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;

	ret = recv(s, pkt, RCVPKTSIZE, MSG_TRUNC);
	if (ret < sizeof(*eth)+sizeof(*ip)) {
		return -1;
	}

	/* Ethernet */
	eth = (struct ether_header *)pkt;

	/* we want either IPv4 or IPv6 */
	if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		/* IP */
		ip = (struct iphdr *)(eth+1);

		/* We only want IPv4 packets */
		if (ip->version != 4) {
			return -1;
		}
		/* Dont look at fragments */
		if ((ntohs(ip->frag_off)&0x1fff) != 0) {
			return -1;
		}
		/* we only want TCP */
		if (ip->protocol != IPPROTO_TCP) {
			return -1;
		}

		/* make sure its not a short packet */
		if (offsetof(struct tcphdr, ack_seq) + 4 + 
		    (ip->ihl*4) + sizeof(*eth) > ret) {
			return -1;
		}
		/* TCP */
		tcp = (struct tcphdr *)((ip->ihl*4) + (char *)ip);

		/* tell the caller which one we've found */
		src->ip.sin_family      = AF_INET;
		src->ip.sin_addr.s_addr = ip->saddr;
		src->ip.sin_port        = tcp->source;
		dst->ip.sin_family      = AF_INET;
		dst->ip.sin_addr.s_addr = ip->daddr;
		dst->ip.sin_port        = tcp->dest;
		*ack_seq                = tcp->ack_seq;
		*seq                    = tcp->seq;
		if (window != NULL) {
			*window = tcp->window;
		}
		if (rst != NULL) {
			*rst = tcp->rst;
		}

		return 0;
	} else if (ntohs(eth->ether_type) == ETHERTYPE_IP6) {
		/* IP6 */
		ip6 = (struct ip6_hdr *)(eth+1);

		/* we only want TCP */
		if (ip6->ip6_nxt != IPPROTO_TCP) {
			return -1;
		}

		/* TCP */
		tcp = (struct tcphdr *)(ip6+1);

		/* tell the caller which one we've found */
		src->ip6.sin6_family = AF_INET6;
		src->ip6.sin6_port   = tcp->source;
		src->ip6.sin6_addr   = ip6->ip6_src;

		dst->ip6.sin6_family = AF_INET6;
		dst->ip6.sin6_port   = tcp->dest;
		dst->ip6.sin6_addr   = ip6->ip6_dst;

		*ack_seq             = tcp->ack_seq;
		*seq                 = tcp->seq;
		if (window != NULL) {
			*window = tcp->window;
		}
		if (rst != NULL) {
			*rst = tcp->rst;
		}

		return 0;
	}

	return -1;
}

bool ctdb_sys_check_iface_exists(const char *iface)
{
	/* FIXME kFreeBSD: Interface always considered present */
	return true;
}

int ctdb_get_peer_pid(const int fd, pid_t *peer_pid)
{
	/* FIXME kFreeBSD: get_peer_pid not implemented */
	return 1;
}

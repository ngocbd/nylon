/*
 * net.h
 *
 * Copyright (c) 2001, 2002 Marius Aamodt Eriksen <marius@monkey.org>
 * 
 * $Id: net.h,v 1.6 2003/06/08 05:56:47 marius Exp $
 */

#ifndef NET_H
#define NET_H

#define NET_STATE_EOFPENDING 0x1

#define NET_SUPPORT_SOCKS4 0x01
#define NET_SUPPORT_SOCKS5 0x02

struct conndesc {
	struct addrinfo *mirror_ai;
	struct addrinfo *bind_ai;
	struct addrinfo *serv_ai;
	struct addrinfo *chain_ai;
	int              support;
};

int net_setup(char *, char *, char *, char *, char *, int);

#endif /* NET_H */

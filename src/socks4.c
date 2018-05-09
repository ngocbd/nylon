/*
 * socks4.c
 *
 * Copyright (c) 2001, 2002 Marius Aamodt Eriksen <marius@monkey.org>
 *
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "atomicio.h"
#include "print.h"
#include "net.h"

#define SOCKS4_MAX_USERID   1024
#define SOCKS4_CD_CONNECT   1
#define SOCKS4_CD_BIND      2
#define SOCKS4_CD_GRANT     90
#define SOCKS4_CD_REJECT    91

struct socks4_hdr {
	u_char    vn;
	u_char    cd;
	u_int16_t destport;     
	u_int32_t destaddr;  
};

static int socks4_connect(int, struct sockaddr_in *, struct socks4_hdr *,
    struct conndesc *);

int
socks4_negotiate(int clisock, struct conndesc *conn)
{
	u_char junk;
	int remsock, ret;
	struct socks4_hdr hdr4;
	struct sockaddr_in rem_in;

	/* This is already implied ... */
	hdr4.vn = 4;

	ret = -1;
	
	/* Get the seven first bytes after version, until USERID */
	if (atomicio(read, clisock, &hdr4.cd, 7) != 7) 
		return (-1);

	/* Eat the username; it is not used */
	while ((ret = atomicio(read, clisock, &junk, 1)) == 1 && junk != 0);

	if (ret != 1)
		return (-1);

	memset(&rem_in, 0, sizeof(rem_in));
	rem_in.sin_family = AF_INET;
	rem_in.sin_port = hdr4.destport;
	rem_in.sin_addr.s_addr = hdr4.destaddr;

	switch (hdr4.cd) {
	case SOCKS4_CD_CONNECT:
		remsock = socks4_connect(clisock, &rem_in, &hdr4, conn);
		break;
	default:
		return (-1);
	}
		

	return (remsock);
}

static int
socks4_connect(int clisock, struct sockaddr_in *rem_in, struct socks4_hdr *hdr4,
    struct conndesc *conn)
{
	struct addrinfo *ai;
	int remsock;

	if ((remsock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return (-1);

	if ((ai = conn->bind_ai) != NULL)
		if (bind(remsock, ai->ai_addr, ai->ai_addrlen) == -1) {
			warnv(0, "bind()");
			return (-1);
		}

	if (connect(remsock, (struct sockaddr *)rem_in,
		sizeof(*rem_in)) == -1) {
		warnv(0, "connect()");
		hdr4->cd = SOCKS4_CD_REJECT;
	} else {
		hdr4->cd = SOCKS4_CD_GRANT;
	}
	
	hdr4->vn = 0; 

	if (atomicio(write, clisock, hdr4, sizeof(*hdr4)) != sizeof(*hdr4))
		goto fail;

	if (hdr4->cd == SOCKS4_CD_REJECT)
		goto fail;

	return (remsock);
 fail:
	close(remsock);
	return (-1);
}

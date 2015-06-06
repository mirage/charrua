/*
 * Copyright (c) 2015 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#ifdef IP_RECVIF
#include <net/if_dl.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "caml/memory.h"
#include "caml/fail.h"
#include "caml/unixsupport.h"
#include "caml/signals.h"
#include "caml/alloc.h"
#include "caml/custom.h"
#include "caml/bigarray.h"

CAMLprim value
caml_if_indextoname(value vidx)
{
	CAMLparam1(vidx);
	char buf[IFNAMSIZ];

	if (if_indextoname(Int_val(vidx), buf) == NULL)
		caml_raise_not_found();

	/* Never trust the system */
	buf[IFNAMSIZ - 1] = 0;

	CAMLreturn(caml_copy_string(buf));
}

CAMLprim value
caml_if_nametoindex(value vname)
{
	CAMLparam1(vname);
	int idx = if_nametoindex(String_val(vname));
	if (idx == 0)
		caml_raise_not_found();
	CAMLreturn(Val_int(idx));
}

#if !defined(IP_RECVIF) && !defined(IP_PKTINFO)
#error NO IP_RECVIF or PKTINFO, cant go on :=(.
#endif

#if defined(IP_RECVIF)
#define IP_REQOPT IP_RECVIF
#elif defined(IP_PKTINFO)
#define IP_REQOPT IP_PKTINFO
#endif

CAMLprim value
caml_reqif(value vfd)
{
	CAMLparam1(vfd);
	int yes = 1;

	if (setsockopt(Int_val(vfd), IPPROTO_IP, IP_REQOPT, &yes, sizeof(yes)))
		uerror("reqif: setsockopt", Nothing);

	CAMLreturn (Val_unit);
}

CAMLprim value
caml_recvif(value vfd, value vbuf, value vofs, value vlen)
{
	CAMLparam4(vfd, vbuf, vofs, vlen);
	CAMLlocal1(vres);

	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int)) /* File descriptor passing */
#ifdef IP_RECVIF
		    + CMSG_SPACE(sizeof(struct sockaddr_dl)) /* IP_RECVIF */
#endif
#if defined(IP_RECVDSTADDR)
		    + CMSG_SPACE(sizeof(struct in_addr))     /* IP_RECVDSTADDR */
#elif defined(IP_PKTINFO)
		    + CMSG_SPACE(sizeof(struct in_pktinfo))
#endif
		];
	} cmsgbuf;
	struct iovec		 iov;
	struct msghdr		 msg;
	struct cmsghdr		*cmsg;
	ssize_t			 n;
	size_t			 len;
	char			 iobuf[UNIX_BUFFER_SIZE];
	struct sockaddr_storage	 ss;
#if defined(IP_RECVIF)
	struct sockaddr_dl	*dst;
#elif defined(IP_PKTINFO)
	struct in_pktinfo	*pktinfo;
#endif
	int			 ifidx = -1;

	len = Long_val(vlen);

	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));

	if (len > UNIX_BUFFER_SIZE)
		len = UNIX_BUFFER_SIZE;

	iov.iov_base = iobuf;
	iov.iov_len = len;
	msg.msg_name = &ss;
	msg.msg_namelen = sizeof(ss);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	caml_enter_blocking_section();
	n = recvmsg(Int_val(vfd), &msg, 0);
	caml_leave_blocking_section();

	if (n == -1) {
		uerror("recvif", Nothing);
		CAMLreturn (Val_unit);
	}

	memmove(&Byte(vbuf, Long_val(vofs)), iobuf, n);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#if defined(IP_RECVIF)
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_RECVIF) {
			dst = (struct sockaddr_dl *)CMSG_DATA(cmsg);
			ifidx = dst->sdl_index;
			continue;
		}
#elif defined(IP_PKTINFO)
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_PKTINFO) {
			pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			ifidx = pktinfo->ipi_ifindex;
			continue;
		}
#endif

#if 0
/* #ifdef IP_RECVDSTADDR */
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_RECVDSTADDR) {
			struct in_addr ipdst;
			ipdst = *(struct in_addr *)CMSG_DATA(cmsg);
			v = caml_alloc_small(2, 0);
			vx = caml_alloc_small(1, TAG_IP_RECVDSTADDR);
			Field(vx, 0) = caml_alloc_string(4);
			memcpy(String_val(Field(vx, 0)), &ipdst, 4);
			Field(v, 0) = vx;
			Field(v, 1) = vlist;
			vlist = v;
			continue;
		}
#endif
	}

	if (ifidx == -1) {
		caml_raise_not_found();
		return (Val_unit);
	}
	vres = caml_alloc_small(2, 0);
	Field(vres, 0) = Val_long(n);
	Field(vres, 1) = Val_int(ifidx);

	CAMLreturn (vres);
}

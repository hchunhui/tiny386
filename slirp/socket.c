/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include "slirp.h"
#include "ip_icmp.h"

static void sofcantrcvmore(struct socket *so);
static void sofcantsendmore(struct socket *so);

struct socket *
solookup(struct socket *head, struct in_addr laddr, u_int lport,
         struct in_addr faddr, u_int fport)
{
	struct socket *so;

	for (so = head->so_next; so != head; so = so->so_next) {
		if (so->so_lport == lport &&
		    so->so_laddr.s_addr == laddr.s_addr &&
		    so->so_faddr.s_addr == faddr.s_addr &&
		    so->so_fport == fport)
		   break;
	}

	if (so == head)
	   return (struct socket *)NULL;
	return so;

}

/*
 * Create a new socket, initialise the fields
 * It is the responsibility of the caller to
 * insque() it into the correct linked-list
 */
struct socket *
socreate(Slirp *slirp)
{
  struct socket *so;

  so = (struct socket *)malloc(sizeof(struct socket));
  if(so) {
    memset(so, 0, sizeof(struct socket));
    so->so_state = SS_NOFDREF;
    so->s = -1;
    so->slirp = slirp;
  }
  return(so);
}

/*
 * remque and free a socket, clobber cache
 */
void
sofree(struct socket *so)
{
  Slirp *slirp = so->slirp;

  if (so->so_emu==EMU_RSH && so->extra) {
	sofree(so->extra);
	so->extra=NULL;
  }
  if (so == slirp->tcp_last_so) {
      slirp->tcp_last_so = &slirp->tcb;
  } else if (so == slirp->udp_last_so) {
      slirp->udp_last_so = &slirp->udb;
  } else if (so == slirp->icmp_last_so) {
      slirp->icmp_last_so = &slirp->icmp;
  }
  m_free(so->so_m);

  if(so->so_next && so->so_prev)
    remque(so);  /* crashes if so is not in a queue */

  free(so);
}

size_t sopreprbuf(struct socket *so, struct iovec *iov, int *np)
{
	int n, lss, total;
	struct sbuf *sb = &so->so_snd;
	int len = sb->sb_datalen - sb->sb_cc;
	int mss = so->so_tcpcb->t_maxseg;

	DEBUG_CALL("sopreprbuf");
	DEBUG_ARG("so = %lx", (long )so);

	if (len <= 0)
		return 0;

	iov[0].iov_base = sb->sb_wptr;
        iov[1].iov_base = NULL;
        iov[1].iov_len = 0;
	if (sb->sb_wptr < sb->sb_rptr) {
		iov[0].iov_len = sb->sb_rptr - sb->sb_wptr;
		/* Should never succeed, but... */
		if (iov[0].iov_len > len)
		   iov[0].iov_len = len;
		if (iov[0].iov_len > mss)
		   iov[0].iov_len -= iov[0].iov_len%mss;
		n = 1;
	} else {
		iov[0].iov_len = (sb->sb_data + sb->sb_datalen) - sb->sb_wptr;
		/* Should never succeed, but... */
		if (iov[0].iov_len > len) iov[0].iov_len = len;
		len -= iov[0].iov_len;
		if (len) {
			iov[1].iov_base = sb->sb_data;
			iov[1].iov_len = sb->sb_rptr - sb->sb_data;
			if(iov[1].iov_len > len)
			   iov[1].iov_len = len;
			total = iov[0].iov_len + iov[1].iov_len;
			if (total > mss) {
				lss = total%mss;
				if (iov[1].iov_len > lss) {
					iov[1].iov_len -= lss;
					n = 2;
				} else {
					lss -= iov[1].iov_len;
					iov[0].iov_len -= lss;
					n = 1;
				}
			} else
				n = 2;
		} else {
			if (iov[0].iov_len > mss)
			   iov[0].iov_len -= iov[0].iov_len%mss;
			n = 1;
		}
	}
	if (np)
		*np = n;

	return iov[0].iov_len + (n - 1) * iov[1].iov_len;
}

/*
 * Read from so's socket into sb_snd, updating all relevant sbuf fields
 * NOTE: This will only be called if it is select()ed for reading, so
 * a read() of 0 (or less) means it's disconnected
 */
int
soread(struct socket *so)
{
	int n, nn;
	struct sbuf *sb = &so->so_snd;
	struct iovec iov[2];

	DEBUG_CALL("soread");
	DEBUG_ARG("so = %lx", (long )so);

	/*
	 * No need to check if there's enough room to read.
	 * soread wouldn't have been called if there weren't
	 */
	sopreprbuf(so, iov, &n);

#ifdef HAVE_READV
	nn = readv(so->s, (struct iovec *)iov, n);
	DEBUG_MISC((dfd, " ... read nn = %d bytes\n", nn));
#else
	nn = recv(so->s, iov[0].iov_base, iov[0].iov_len,0);
#endif
	if (nn <= 0) {
		if (nn < 0 && (errno == EINTR || errno == EAGAIN))
			return 0;
		else {
			DEBUG_MISC((dfd, " --- soread() disconnected, nn = %d, errno = %d-%s\n", nn, errno,strerror(errno)));
			sofcantrcvmore(so);
			tcp_sockclosed(sototcpcb(so));
			return -1;
		}
	}

#ifndef HAVE_READV
	/*
	 * If there was no error, try and read the second time round
	 * We read again if n = 2 (ie, there's another part of the buffer)
	 * and we read as much as we could in the first read
	 * We don't test for <= 0 this time, because there legitimately
	 * might not be any more data (since the socket is non-blocking),
	 * a close will be detected on next iteration.
	 * A return of -1 wont (shouldn't) happen, since it didn't happen above
	 */
	if (n == 2 && nn == iov[0].iov_len) {
            int ret;
            ret = recv(so->s, iov[1].iov_base, iov[1].iov_len,0);
            if (ret > 0)
                nn += ret;
        }

	DEBUG_MISC((dfd, " ... read nn = %d bytes\n", nn));
#endif

	/* Update fields */
	sb->sb_cc += nn;
	sb->sb_wptr += nn;
	if (sb->sb_wptr >= (sb->sb_data + sb->sb_datalen))
		sb->sb_wptr -= sb->sb_datalen;
	return nn;
}

int soreadbuf(struct socket *so, const char *buf, int size)
{
    int n, nn, copy = size;
	struct sbuf *sb = &so->so_snd;
	struct iovec iov[2];

	DEBUG_CALL("soreadbuf");
	DEBUG_ARG("so = %lx", (long )so);

	/*
	 * No need to check if there's enough room to read.
	 * soread wouldn't have been called if there weren't
	 */
	if (sopreprbuf(so, iov, &n) < size)
        goto err;

    nn = min(iov[0].iov_len, copy);
    memcpy(iov[0].iov_base, buf, nn);

    copy -= nn;
    buf += nn;

    if (copy == 0)
        goto done;

    memcpy(iov[1].iov_base, buf, copy);

done:
    /* Update fields */
	sb->sb_cc += size;
	sb->sb_wptr += size;
	if (sb->sb_wptr >= (sb->sb_data + sb->sb_datalen))
		sb->sb_wptr -= sb->sb_datalen;
    return size;
err:

    sofcantrcvmore(so);
    tcp_sockclosed(sototcpcb(so));
    fprintf(stderr, "soreadbuf buffer to small");
    return -1;
}

/*
 * Get urgent data
 *
 * When the socket is created, we set it SO_OOBINLINE,
 * so when OOB data arrives, we soread() it and everything
 * in the send buffer is sent as urgent data
 */
void
sorecvoob(struct socket *so)
{
	struct tcpcb *tp = sototcpcb(so);

	DEBUG_CALL("sorecvoob");
	DEBUG_ARG("so = %lx", (long)so);

	/*
	 * We take a guess at how much urgent data has arrived.
	 * In most situations, when urgent data arrives, the next
	 * read() should get all the urgent data.  This guess will
	 * be wrong however if more data arrives just after the
	 * urgent data, or the read() doesn't return all the
	 * urgent data.
	 */
	soread(so);
	tp->snd_up = tp->snd_una + so->so_snd.sb_cc;
	tp->t_force = 1;
	tcp_output(tp);
	tp->t_force = 0;
}

/*
 * Send urgent data
 * There's a lot duplicated code here, but...
 */
int
sosendoob(struct socket *so)
{
	struct sbuf *sb = &so->so_rcv;
	char buff[2048]; /* XXX Shouldn't be sending more oob data than this */

	int n, len;

	DEBUG_CALL("sosendoob");
	DEBUG_ARG("so = %lx", (long)so);
	DEBUG_ARG("sb->sb_cc = %d", sb->sb_cc);

	if (so->so_urgc > 2048)
	   so->so_urgc = 2048; /* XXXX */

	if (sb->sb_rptr < sb->sb_wptr) {
		/* We can send it directly */
		n = slirp_send(so, sb->sb_rptr, so->so_urgc, (MSG_OOB)); /* |MSG_DONTWAIT)); */
		so->so_urgc -= n;

		DEBUG_MISC((dfd, " --- sent %d bytes urgent data, %d urgent bytes left\n", n, so->so_urgc));
	} else {
		/*
		 * Since there's no sendv or sendtov like writev,
		 * we must copy all data to a linear buffer then
		 * send it all
		 */
		len = (sb->sb_data + sb->sb_datalen) - sb->sb_rptr;
		if (len > so->so_urgc) len = so->so_urgc;
		memcpy(buff, sb->sb_rptr, len);
		so->so_urgc -= len;
		if (so->so_urgc) {
			n = sb->sb_wptr - sb->sb_data;
			if (n > so->so_urgc) n = so->so_urgc;
			memcpy((buff + len), sb->sb_data, n);
			so->so_urgc -= n;
			len += n;
		}
		n = slirp_send(so, buff, len, (MSG_OOB)); /* |MSG_DONTWAIT)); */
#ifdef DEBUG
		if (n != len)
		   DEBUG_ERROR((dfd, "Didn't send all data urgently XXXXX\n"));
#endif
		DEBUG_MISC((dfd, " ---2 sent %d bytes urgent data, %d urgent bytes left\n", n, so->so_urgc));
	}

	sb->sb_cc -= n;
	sb->sb_rptr += n;
	if (sb->sb_rptr >= (sb->sb_data + sb->sb_datalen))
		sb->sb_rptr -= sb->sb_datalen;

	return n;
}

/*
 * Write data from so_rcv to so's socket,
 * updating all sbuf field as necessary
 */
int
sowrite(struct socket *so)
{
	int  n,nn;
	struct sbuf *sb = &so->so_rcv;
	int len = sb->sb_cc;
	struct iovec iov[2];

	DEBUG_CALL("sowrite");
	DEBUG_ARG("so = %lx", (long)so);

	if (so->so_urgc) {
		sosendoob(so);
		if (sb->sb_cc == 0)
			return 0;
	}

	/*
	 * No need to check if there's something to write,
	 * sowrite wouldn't have been called otherwise
	 */

	iov[0].iov_base = sb->sb_rptr;
        iov[1].iov_base = NULL;
        iov[1].iov_len = 0;
	if (sb->sb_rptr < sb->sb_wptr) {
		iov[0].iov_len = sb->sb_wptr - sb->sb_rptr;
		/* Should never succeed, but... */
		if (iov[0].iov_len > len) iov[0].iov_len = len;
		n = 1;
	} else {
		iov[0].iov_len = (sb->sb_data + sb->sb_datalen) - sb->sb_rptr;
		if (iov[0].iov_len > len) iov[0].iov_len = len;
		len -= iov[0].iov_len;
		if (len) {
			iov[1].iov_base = sb->sb_data;
			iov[1].iov_len = sb->sb_wptr - sb->sb_data;
			if (iov[1].iov_len > len) iov[1].iov_len = len;
			n = 2;
		} else
			n = 1;
	}
	/* Check if there's urgent data to send, and if so, send it */

#ifdef HAVE_READV
	nn = writev(so->s, (const struct iovec *)iov, n);

	DEBUG_MISC((dfd, "  ... wrote nn = %d bytes\n", nn));
#else
	nn = slirp_send(so, iov[0].iov_base, iov[0].iov_len,0);
#endif
	/* This should never happen, but people tell me it does *shrug* */
	if (nn < 0 && (errno == EAGAIN || errno == EINTR))
		return 0;

	if (nn <= 0) {
		DEBUG_MISC((dfd, " --- sowrite disconnected, so->so_state = %x, errno = %d\n",
			so->so_state, errno));
		sofcantsendmore(so);
		tcp_sockclosed(sototcpcb(so));
		return -1;
	}

#ifndef HAVE_READV
	if (n == 2 && nn == iov[0].iov_len) {
            int ret;
            ret = slirp_send(so, iov[1].iov_base, iov[1].iov_len,0);
            if (ret > 0)
                nn += ret;
        }
        DEBUG_MISC((dfd, "  ... wrote nn = %d bytes\n", nn));
#endif

	/* Update sbuf */
	sb->sb_cc -= nn;
	sb->sb_rptr += nn;
	if (sb->sb_rptr >= (sb->sb_data + sb->sb_datalen))
		sb->sb_rptr -= sb->sb_datalen;

	/*
	 * If in DRAIN mode, and there's no more data, set
	 * it CANTSENDMORE
	 */
	if ((so->so_state & SS_FWDRAIN) && sb->sb_cc == 0)
		sofcantsendmore(so);

	return nn;
}

/*
 * recvfrom() a UDP socket
 */
void
sorecvfrom(struct socket *so)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	DEBUG_CALL("sorecvfrom");
	DEBUG_ARG("so = %lx", (long)so);

	if (so->so_type == IPPROTO_ICMP) {   /* This is a "ping" reply */
	  char buff[256];
	  int len;

	  len = recvfrom(so->s, buff, 256, 0,
			 (struct sockaddr *)&addr, &addrlen);
	  /* XXX Check if reply is "correct"? */

	  if(len == -1 || len == 0) {
	    u_char code=ICMP_UNREACH_PORT;

	    if(errno == EHOSTUNREACH) code=ICMP_UNREACH_HOST;
	    else if(errno == ENETUNREACH) code=ICMP_UNREACH_NET;

	    DEBUG_MISC((dfd," udp icmp rx errno = %d-%s\n",
			errno,strerror(errno)));
	    icmp_error(so->so_m, ICMP_UNREACH,code, 0,strerror(errno));
	  } else {
	    icmp_reflect(so->so_m);
            so->so_m = NULL; /* Don't m_free() it again! */
	  }
	  /* No need for this socket anymore, udp_detach it */
	  udp_detach(so);
	} else {                            	/* A "normal" UDP packet */
	  struct mbuf *m;
          int len;
#ifdef _WIN32
          unsigned long n;
#else
          int n;
#endif

	  m = m_get(so->slirp);
	  if (!m) {
	      return;
	  }
	  m->m_data += IF_MAXLINKHDR;

	  /*
	   * XXX Shouldn't FIONREAD packets destined for port 53,
	   * but I don't know the max packet size for DNS lookups
	   */
	  len = M_FREEROOM(m);
	  /* if (so->so_fport != htons(53)) { */
	  ioctlsocket(so->s, FIONREAD, &n);

	  if (n > len) {
	    n = (m->m_data - m->m_dat) + m->m_len + n + 1;
	    m_inc(m, n);
	    len = M_FREEROOM(m);
	  }
	  /* } */

	  m->m_len = recvfrom(so->s, m->m_data, len, 0,
			      (struct sockaddr *)&addr, &addrlen);
	  DEBUG_MISC((dfd, " did recvfrom %d, errno = %d-%s\n",
		      m->m_len, errno,strerror(errno)));
	  if(m->m_len<0) {
	    u_char code=ICMP_UNREACH_PORT;

	    if(errno == EHOSTUNREACH) code=ICMP_UNREACH_HOST;
	    else if(errno == ENETUNREACH) code=ICMP_UNREACH_NET;

	    DEBUG_MISC((dfd," rx error, tx icmp ICMP_UNREACH:%i\n", code));
	    icmp_error(so->so_m, ICMP_UNREACH,code, 0,strerror(errno));
	    m_free(m);
	  } else {
	  /*
	   * Hack: domain name lookup will be used the most for UDP,
	   * and since they'll only be used once there's no need
	   * for the 4 minute (or whatever) timeout... So we time them
	   * out much quicker (10 seconds  for now...)
	   */
	    if (so->so_expire) {
	      if (so->so_fport == htons(53))
		so->so_expire = curtime + SO_EXPIREFAST;
	      else
		so->so_expire = curtime + SO_EXPIRE;
	    }

	    /*
	     * If this packet was destined for CTL_ADDR,
	     * make it look like that's where it came from, done by udp_output
	     */
	    udp_output(so, m, &addr);
	  } /* rx error */
	} /* if ping packet */
}

/*
 * sendto() a socket
 */
int
sosendto(struct socket *so, struct mbuf *m)
{
	Slirp *slirp = so->slirp;
	int ret;
	struct sockaddr_in addr;

	DEBUG_CALL("sosendto");
	DEBUG_ARG("so = %lx", (long)so);
	DEBUG_ARG("m = %lx", (long)m);

        addr.sin_family = AF_INET;
	if ((so->so_faddr.s_addr & slirp->vnetwork_mask.s_addr) ==
	    slirp->vnetwork_addr.s_addr) {
	  /* It's an alias */
	  if (so->so_faddr.s_addr == slirp->vnameserver_addr.s_addr) {
	    if (get_dns_addr(&addr.sin_addr) < 0)
	      addr.sin_addr = loopback_addr;
	  } else {
	    addr.sin_addr = loopback_addr;
	  }
	} else
	  addr.sin_addr = so->so_faddr;
	addr.sin_port = so->so_fport;

	DEBUG_MISC((dfd, " sendto()ing, addr.sin_port=%d, addr.sin_addr.s_addr=%.16s\n", ntohs(addr.sin_port), inet_ntoa(addr.sin_addr)));

	/* Don't care what port we get */
	ret = sendto(so->s, m->m_data, m->m_len, 0,
		     (struct sockaddr *)&addr, sizeof (struct sockaddr));
	if (ret < 0)
		return -1;

	/*
	 * Kill the socket if there's no reply in 4 minutes,
	 * but only if it's an expirable socket
	 */
	if (so->so_expire)
		so->so_expire = curtime + SO_EXPIRE;
	so->so_state &= SS_PERSISTENT_MASK;
	so->so_state |= SS_ISFCONNECTED; /* So that it gets select()ed */
	return 0;
}

/*
 * Listen for incoming TCP connections
 */
struct socket *
tcp_listen(Slirp *slirp, uint32_t haddr, u_int hport, uint32_t laddr,
           u_int lport, int flags)
{
	struct sockaddr_in addr;
	struct socket *so;
	int s, opt = 1;
	socklen_t addrlen = sizeof(addr);
	memset(&addr, 0, addrlen);

	DEBUG_CALL("tcp_listen");
	DEBUG_ARG("haddr = %x", haddr);
	DEBUG_ARG("hport = %d", hport);
	DEBUG_ARG("laddr = %x", laddr);
	DEBUG_ARG("lport = %d", lport);
	DEBUG_ARG("flags = %x", flags);

	so = socreate(slirp);
	if (!so) {
	  return NULL;
	}

	/* Don't tcp_attach... we don't need so_snd nor so_rcv */
	if ((so->so_tcpcb = tcp_newtcpcb(so)) == NULL) {
		free(so);
		return NULL;
	}
	insque(so, &slirp->tcb);

	/*
	 * SS_FACCEPTONCE sockets must time out.
	 */
	if (flags & SS_FACCEPTONCE)
	   so->so_tcpcb->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT*2;

	so->so_state &= SS_PERSISTENT_MASK;
	so->so_state |= (SS_FACCEPTCONN | flags);
	so->so_lport = lport; /* Kept in network format */
	so->so_laddr.s_addr = laddr; /* Ditto */

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = haddr;
	addr.sin_port = hport;

	if (((s = os_socket(AF_INET,SOCK_STREAM,0)) < 0) ||
	    (setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char *)&opt,sizeof(int)) < 0) ||
	    (bind(s,(struct sockaddr *)&addr, sizeof(addr)) < 0) ||
	    (listen(s,1) < 0)) {
		int tmperrno = errno; /* Don't clobber the real reason we failed */

		close(s);
		sofree(so);
		/* Restore the real errno */
#ifdef _WIN32
		WSASetLastError(tmperrno);
#else
		errno = tmperrno;
#endif
		return NULL;
	}
	setsockopt(s,SOL_SOCKET,SO_OOBINLINE,(char *)&opt,sizeof(int));

	getsockname(s,(struct sockaddr *)&addr,&addrlen);
	so->so_fport = addr.sin_port;
	if (addr.sin_addr.s_addr == 0 || addr.sin_addr.s_addr == loopback_addr.s_addr)
	   so->so_faddr = slirp->vhost_addr;
	else
	   so->so_faddr = addr.sin_addr;

	so->s = s;
	return so;
}

/*
 * Various session state calls
 * XXX Should be #define's
 * The socket state stuff needs work, these often get call 2 or 3
 * times each when only 1 was needed
 */
void
soisfconnecting(struct socket *so)
{
	so->so_state &= ~(SS_NOFDREF|SS_ISFCONNECTED|SS_FCANTRCVMORE|
			  SS_FCANTSENDMORE|SS_FWDRAIN);
	so->so_state |= SS_ISFCONNECTING; /* Clobber other states */
}

void
soisfconnected(struct socket *so)
{
	so->so_state &= ~(SS_ISFCONNECTING|SS_FWDRAIN|SS_NOFDREF);
	so->so_state |= SS_ISFCONNECTED; /* Clobber other states */
}

static void
sofcantrcvmore(struct socket *so)
{
	if ((so->so_state & SS_NOFDREF) == 0) {
		shutdown(so->s,0);
		if(global_writefds) {
		  FD_CLR(so->s,global_writefds);
		}
	}
	so->so_state &= ~(SS_ISFCONNECTING);
	if (so->so_state & SS_FCANTSENDMORE) {
	   so->so_state &= SS_PERSISTENT_MASK;
	   so->so_state |= SS_NOFDREF; /* Don't select it */
	} else {
	   so->so_state |= SS_FCANTRCVMORE;
	}
}

static void
sofcantsendmore(struct socket *so)
{
	if ((so->so_state & SS_NOFDREF) == 0) {
            shutdown(so->s,1);           /* send FIN to fhost */
            if (global_readfds) {
                FD_CLR(so->s,global_readfds);
            }
            if (global_xfds) {
                FD_CLR(so->s,global_xfds);
            }
	}
	so->so_state &= ~(SS_ISFCONNECTING);
	if (so->so_state & SS_FCANTRCVMORE) {
	   so->so_state &= SS_PERSISTENT_MASK;
	   so->so_state |= SS_NOFDREF; /* as above */
	} else {
	   so->so_state |= SS_FCANTSENDMORE;
	}
}

/*
 * Set write drain mode
 * Set CANTSENDMORE once all data has been write()n
 */
void
sofwdrain(struct socket *so)
{
	if (so->so_rcv.sb_cc)
		so->so_state |= SS_FWDRAIN;
	else
		sofcantsendmore(so);
}

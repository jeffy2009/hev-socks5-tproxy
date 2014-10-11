/*
 ============================================================================
 Name        : hev-socks5-tproxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 transparent proxy
 ============================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hev-socks5-tproxy.h"
#include "hev-socks5-session.h"

#define TIMEOUT		(30 * 1000)

struct _HevSocks5TProxy
{
	int listen_fd;
	unsigned int ref_count;
	HevEventSource *listener_source;
	HevEventSource *timeout_source;
	HevSList *session_list;

	HevEventLoop *loop;
	struct sockaddr_in saddr;
};

static bool listener_source_handler (HevEventSourceFD *fd, void *data);
static bool timeout_source_handler (void *data);
static void session_close_handler (HevSocks5Session *session, void *data);

HevSocks5TProxy *
hev_socks5_tproxy_new (HevEventLoop *loop, const char *laddr, unsigned short lport,
			const char *saddr, unsigned short sport)
{
	HevSocks5TProxy *self = HEV_MEMORY_ALLOCATOR_ALLOC (sizeof (HevSocks5TProxy));
	if (self) {
		int nonblock = 1, reuseaddr = 1;
		struct sockaddr_in iaddr;

		/* listen socket */
		self->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
		if (0 > self->listen_fd) {
			HEV_MEMORY_ALLOCATOR_FREE (self);
			return NULL;
		}
		ioctl (self->listen_fd, FIONBIO, (char *) &nonblock);
		setsockopt (self->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof (reuseaddr));
		memset (&iaddr, 0, sizeof (iaddr));
		iaddr.sin_family = AF_INET;
		iaddr.sin_addr.s_addr = inet_addr (laddr);
		iaddr.sin_port = htons (lport);
		if ((0 > bind (self->listen_fd, (struct sockaddr *) &iaddr, (socklen_t) sizeof (iaddr))) ||
					(0 > listen (self->listen_fd, 100))) {
			close (self->listen_fd);
			HEV_MEMORY_ALLOCATOR_FREE (self);
			return NULL;
		}

		/* remote address */
		memset (&self->saddr, 0, sizeof (self->saddr));
		self->saddr.sin_family = AF_INET;
		self->saddr.sin_addr.s_addr = inet_addr (saddr);
		self->saddr.sin_port = htons (sport);

		/* event source fds for listener */
		self->listener_source = hev_event_source_fds_new ();
		hev_event_source_set_priority (self->listener_source, 1);
		hev_event_source_add_fd (self->listener_source, self->listen_fd, EPOLLIN | EPOLLET);
		hev_event_source_set_callback (self->listener_source,
					(HevEventSourceFunc) listener_source_handler, self, NULL);
		hev_event_loop_add_source (loop, self->listener_source);
		hev_event_source_unref (self->listener_source);

		/* event source timeout */
		self->timeout_source = hev_event_source_timeout_new (TIMEOUT);
		hev_event_source_set_priority (self->timeout_source, -1);
		hev_event_source_set_callback (self->timeout_source, timeout_source_handler, self, NULL);
		hev_event_loop_add_source (loop, self->timeout_source);
		hev_event_source_unref (self->timeout_source);

		self->ref_count = 1;
		self->session_list = NULL;
		self->loop = loop;
	}

	return self;
}

HevSocks5TProxy *
hev_socks5_tproxy_ref (HevSocks5TProxy *self)
{
	if (self) {
		self->ref_count ++;
		return self;
	}

	return NULL;
}

void
hev_socks5_tproxy_unref (HevSocks5TProxy *self)
{
	if (self) {
		self->ref_count --;
		if (0 == self->ref_count) {
			hev_event_loop_del_source (self->loop, self->listener_source);
			hev_event_loop_del_source (self->loop, self->timeout_source);
			close (self->listen_fd);
			HEV_MEMORY_ALLOCATOR_FREE (self);
		}
	}
}

static bool
listener_source_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5TProxy *self = data;
	struct sockaddr_in addr;
	socklen_t addr_len;
	int client_fd = -1;

	addr_len = sizeof (addr);
	client_fd = accept (fd->fd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
	if (0 > client_fd) {
		if (EAGAIN == errno)
		  fd->revents &= ~EPOLLIN;
		else
		  printf ("Accept failed!\n");
	} else {
		HevSocks5Session *session = NULL;
		HevEventSource *source = NULL;
		int remote_fd = -1, nonblock = 1;

		/* create remote socket */
		remote_fd = socket (AF_INET, SOCK_STREAM, 0);
		ioctl (remote_fd, FIONBIO, (char *) &nonblock);
		connect (remote_fd, (struct sockaddr *) &self->saddr, sizeof (self->saddr));

		/* new session */
		session = hev_socks5_session_new (client_fd, remote_fd, session_close_handler, self);
		source = hev_socks5_session_get_source (session);
		hev_event_loop_add_source (self->loop, source);
		/* printf ("New session %p (%d) enter from %s:%u\n", session,
					client_fd, inet_ntoa (addr.sin_addr), ntohs (addr.sin_port)); */

		self->session_list = hev_slist_append (self->session_list, session);
	}

	return true;
}

static bool
timeout_source_handler (void *data)
{
	HevSocks5TProxy *self = data;
	HevSList *list = NULL;
	for (list=self->session_list; list; list=hev_slist_next (list)) {
		HevSocks5Session *session = hev_slist_data (list);
		if (hev_socks5_session_get_idle (session)) {
			/* printf ("Remove timeout session %p\n", session); */
			hev_event_loop_del_source (self->loop,
						hev_socks5_session_get_source (session));
			hev_socks5_session_unref (session);
			hev_slist_set_data (list, NULL);
		} else {
			hev_socks5_session_set_idle (session);
		}
	}
	self->session_list = hev_slist_remove_all (self->session_list, NULL);

	return true;
}

static void
session_close_handler (HevSocks5Session *session, void *data)
{
	HevSocks5TProxy *self = data;

	/* printf ("Remove session %p\n", session); */
	hev_event_loop_del_source (self->loop,
				hev_socks5_session_get_source (session));
	hev_socks5_session_unref (session);
	self->session_list = hev_slist_remove (self->session_list, session);
}


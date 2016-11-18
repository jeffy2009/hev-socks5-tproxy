/*
 ============================================================================
 Name        : hev-socks5-session.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 session
 ============================================================================
 */

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>

#include "hev-socks5-session.h"

enum
{
	CLIENT_IN = (1 << 3),
	CLIENT_OUT = (1 << 2),
	REMOTE_IN = (1 << 1),
	REMOTE_OUT = (1 << 0),
};

enum
{
	STEP_NULL,
	STEP_WRITE_AUTH_METHOD,
	STEP_READ_AUTH_METHOD,
	STEP_WRITE_REQUEST,
	STEP_READ_RESPONSE,
	STEP_FWD_DNS_REQUEST,
	STEP_FWD_DNS_RESPONSE,
	STEP_DO_SPLICE,
	STEP_CLOSE_SESSION,
};

struct _HevSocks5Session
{
	int cfd;
	int rfd;
	unsigned int ref_count;
	unsigned int step;
	bool idle;
	uint8_t revents;
	HevSocks5SessionMode mode;
	HevEventSourceFD *client_fd;
	HevEventSourceFD *remote_fd;
	HevRingBuffer *forward_buffer;
	HevRingBuffer *backward_buffer;
	HevRingBuffer *dnsmsg_buffer;
	HevEventSource *source;
	HevSocks5SessionCloseNotify notify;
	void *notify_data;
	struct sockaddr_in addr;
};

static bool session_source_socks5_handler (HevEventSourceFD *fd, void *data);
static bool session_source_splice_handler (HevEventSourceFD *fd, void *data);

HevSocks5Session *
hev_socks5_session_new (int client_fd, int remote_fd, HevSocks5SessionMode mode,
			HevSocks5SessionCloseNotify notify, void *notify_data)
{
	HevSocks5Session *self = HEV_MEMORY_ALLOCATOR_ALLOC (sizeof (HevSocks5Session));
	if (self) {
		struct iovec iovec[2];
		size_t iovec_len = 0;
		struct msghdr mh;
		ssize_t size;
		uint16_t *u16p;

		self->ref_count = 1;
		self->cfd = client_fd;
		self->rfd = remote_fd;
		self->revents = 0;
		self->mode = mode;
		self->idle = false;
		self->client_fd = NULL;
		self->remote_fd = NULL;
		self->forward_buffer = hev_ring_buffer_new (2000);
		self->backward_buffer = hev_ring_buffer_new (2000);
		self->dnsmsg_buffer = NULL;
		self->source = NULL;
		self->step = STEP_NULL;
		self->notify = notify;
		self->notify_data = notify_data;

		if (HEV_SOCKS5_SESSION_MODE_DNS_FWD == mode) {
			self->dnsmsg_buffer = hev_ring_buffer_new (2000);
			iovec_len = hev_ring_buffer_writing (self->dnsmsg_buffer, iovec);
			u16p = iovec[0].iov_base;
			iovec[0].iov_base += 2;
			iovec[0].iov_len -= 2;
			memset (&mh, 0, sizeof (mh));
			mh.msg_iov = iovec;
			mh.msg_iovlen = iovec_len;
			mh.msg_name = &self->addr;
			mh.msg_namelen = sizeof (self->addr);
			size = recvmsg (self->cfd, &mh, 0);
			if (-1 == size) {
				close (self->rfd);
				hev_ring_buffer_unref (self->forward_buffer);
				hev_ring_buffer_unref (self->backward_buffer);
				hev_ring_buffer_unref (self->dnsmsg_buffer);
				HEV_MEMORY_ALLOCATOR_FREE (self);
				return NULL;
			}
			*u16p = htons (size);
			hev_ring_buffer_write_finish (self->dnsmsg_buffer, 2 + size);
		}
	}

	return self;
}

HevSocks5Session *
hev_socks5_session_ref (HevSocks5Session *self)
{
	if (self)
	  self->ref_count ++;

	return self;
}

void
hev_socks5_session_unref (HevSocks5Session *self)
{
	if (self) {
		self->ref_count --;
		if (0 == self->ref_count) {
			if (HEV_SOCKS5_SESSION_MODE_CONNECT == self->mode)
			  close (self->cfd);
			close (self->rfd);
			hev_ring_buffer_unref (self->forward_buffer);
			hev_ring_buffer_unref (self->backward_buffer);
			if (self->dnsmsg_buffer)
			  hev_ring_buffer_unref (self->dnsmsg_buffer);
			if (self->source)
			  hev_event_source_unref (self->source);
			HEV_MEMORY_ALLOCATOR_FREE (self);
		}
	}
}

HevEventSource *
hev_socks5_session_get_source (HevSocks5Session *self)
{
	if (self) {
		if (self->source)
		  return self->source;
		self->source = hev_event_source_fds_new ();
		if (self->source) {
			hev_event_source_set_callback (self->source,
						(HevEventSourceFunc) session_source_socks5_handler, self, NULL);
			self->remote_fd = hev_event_source_add_fd (self->source, self->rfd,
						EPOLLIN | EPOLLOUT | EPOLLET);
		}
		return self->source;
	}

	return NULL;
}

void
hev_socks5_session_set_idle (HevSocks5Session *self)
{
	if (self)
	  self->idle = true;
}

bool
hev_socks5_session_get_idle (HevSocks5Session *self)
{
	return self ? self->idle : false;
}

HevSocks5SessionMode
hev_socks5_session_get_mode (HevSocks5Session *self)
{
	return self->mode;
}

static size_t
iovec_size (struct iovec *iovec, size_t iovec_len)
{
	size_t i = 0, size = 0;

	for (i=0; i<iovec_len; i++)
	  size += iovec[i].iov_len;

	return size;
}

static ssize_t
read_data (int fd, HevRingBuffer *buffer)
{
	struct msghdr mh;
	struct iovec iovec[2];
	size_t iovec_len = 0, inc_len = 0;
	ssize_t size = -2;

	iovec_len = hev_ring_buffer_writing (buffer, iovec);
	if (0 < iovec_len) {
		/* recv data */
		memset (&mh, 0, sizeof (mh));
		mh.msg_iov = iovec;
		mh.msg_iovlen = iovec_len;
		size = recvmsg (fd, &mh, 0);
		inc_len = (0 > size) ? 0 : size;
		hev_ring_buffer_write_finish (buffer, inc_len);
	}

	return size;
}

static ssize_t
write_data (int fd, HevRingBuffer *buffer)
{
	struct msghdr mh;
	struct iovec iovec[2];
	size_t iovec_len = 0, inc_len = 0;
	ssize_t size = -2;

	iovec_len = hev_ring_buffer_reading (buffer, iovec);
	if (0 < iovec_len) {
		/* send data */
		memset (&mh, 0, sizeof (mh));
		mh.msg_iov = iovec;
		mh.msg_iovlen = iovec_len;
		size = sendmsg (fd, &mh, 0);
		inc_len = (0 > size) ? 0 : size;
		hev_ring_buffer_read_finish (buffer, inc_len);
	}

	return size;
}

static bool
client_read (HevSocks5Session *self)
{
	ssize_t size = read_data (self->client_fd->fd, self->forward_buffer);
	if (-2 < size) {
		if (-1 == size) {
			if (EAGAIN == errno) {
				self->revents &= ~CLIENT_IN;
				self->client_fd->revents &= ~EPOLLIN;
			} else {
				return false;
			}
		} else if (0 == size) {
			return false;
		}
	} else {
		self->client_fd->revents &= ~EPOLLIN;
	}

	return true;
}

static bool
client_write (HevSocks5Session *self)
{
	ssize_t size = write_data (self->client_fd->fd, self->backward_buffer);
	if (-2 < size) {
		if (-1 == size) {
			if (EAGAIN == errno) {
				self->revents &= ~CLIENT_OUT;
				self->client_fd->revents &= ~EPOLLOUT;
			} else {
				return false;
			}
		}
	} else {
		self->client_fd->revents &= ~EPOLLOUT;
	}

	return true;
}

static bool
remote_read (HevSocks5Session *self)
{
	ssize_t size = read_data (self->remote_fd->fd, self->backward_buffer);
	if (-2 < size) {
		if (-1 == size) {
			if (EAGAIN == errno) {
				self->revents &= ~REMOTE_IN;
				self->remote_fd->revents &= ~EPOLLIN;
			} else {
				return false;
			}
		} else if (0 == size) {
			return false;
		}
	} else {
		self->remote_fd->revents &= ~EPOLLIN;
	}

	return true;
}

static bool
remote_write (HevSocks5Session *self)
{
	ssize_t size = write_data (self->remote_fd->fd, self->forward_buffer);
	if (-2 < size) {
		if (-1 == size) {
			if (EAGAIN == errno) {
				self->revents &= ~REMOTE_OUT;
				self->remote_fd->revents &= ~EPOLLOUT;
			} else {
				return false;
			}
		}
	} else {
		self->remote_fd->revents &= ~EPOLLOUT;
	}

	return true;
}

static inline bool
socks5_write_auth_method (HevSocks5Session *self)
{
	struct iovec iovec[2];
	uint8_t *data = NULL;

	/* write auth method to ring buffer */
	hev_ring_buffer_writing (self->forward_buffer, iovec);
	data = iovec[0].iov_base;
	data[0] = 0x05;
	data[1] = 0x01;
	data[2] = 0x00;
	hev_ring_buffer_write_finish (self->forward_buffer, 3);

	self->step = STEP_READ_AUTH_METHOD;

	return false;
}

static inline bool
socks5_read_auth_method (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0, size = 0;
	uint8_t *data = NULL;

	iovec_len = hev_ring_buffer_reading (self->backward_buffer, iovec);
	size = iovec_size (iovec, iovec_len);
	if (2 > size)
	  return true;
	data = iovec[0].iov_base;
	if (0x05 != data[0] || 0x00 != data[1]) {
		self->step = STEP_CLOSE_SESSION;
		return false;
	}
	hev_ring_buffer_read_finish (self->backward_buffer, 2);

	self->step = STEP_WRITE_REQUEST;

	return false;
}

static inline bool
socks5_write_request (HevSocks5Session *self)
{
	struct iovec iovec[2];
	uint8_t *data = NULL;
	struct sockaddr_in orig_addr;
	socklen_t orig_addr_len = sizeof (orig_addr);

	if (HEV_SOCKS5_SESSION_MODE_CONNECT == self->mode) {
		/* get original address */
		if (0 != getsockopt (self->cfd, SOL_IP, SO_ORIGINAL_DST,
						(struct sockaddr*) &orig_addr,
						&orig_addr_len)) {
			self->step = STEP_CLOSE_SESSION;
			return false;
		}
	}

	/* write request to ring buffer */
	hev_ring_buffer_writing (self->forward_buffer, iovec);
	data = iovec[0].iov_base;
	data[0] = 0x05;
	data[2] = 0x00;
	data[3] = 0x01;
	if (HEV_SOCKS5_SESSION_MODE_CONNECT == self->mode) {
		data[1] = 0x01;
		memcpy (data+4, &orig_addr.sin_addr, 4);
		memcpy (data+8, &orig_addr.sin_port, 2);
	} else {
		data[1] = 0x04;
	}
	hev_ring_buffer_write_finish (self->forward_buffer, 10);

	self->step = STEP_READ_RESPONSE;

	return false;
}

static inline bool
socks5_read_response (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0, size = 0;
	uint8_t *data = NULL;

	iovec_len = hev_ring_buffer_reading (self->backward_buffer, iovec);
	size = iovec_size (iovec, iovec_len);
	if (4 > size)
	  return true;
	data = iovec[0].iov_base;
	if (0x05 != data[0] || 0x00 != data[1] || 0x01 != data[3]) {
		self->step = STEP_CLOSE_SESSION;
		return false;
	}
	if (10 > size)
	  return true;
	hev_ring_buffer_read_finish (self->backward_buffer, 10);

	if (HEV_SOCKS5_SESSION_MODE_CONNECT == self->mode)
	  self->step = STEP_DO_SPLICE;
	else
	  self->step = STEP_FWD_DNS_REQUEST;

	return false;
}

static inline bool
socks5_fwd_dns_request (HevSocks5Session *self)
{
	HevRingBuffer *buffer;

	/* swap forward_buffer and dnsmsg_buffer */
	buffer = self->forward_buffer;
	self->forward_buffer = self->dnsmsg_buffer;
	self->dnsmsg_buffer = buffer;

	self->step = STEP_FWD_DNS_RESPONSE;

	return false;
}

static inline bool
socks5_fwd_dns_response (HevSocks5Session *self)
{
	struct iovec iovec[2];
	size_t iovec_len = 0, size;
	struct msghdr mh;
	uint16_t request_size;

	iovec_len = hev_ring_buffer_reading (self->backward_buffer, iovec);
	size = iovec_size (iovec, iovec_len);
	if (2 > size)
	  return true;

	if (2 <= iovec[0].iov_len) {
		request_size = ntohs (*(uint16_t *) iovec[0].iov_base);
	} else {
		uint8_t *u8p = (uint8_t *) &request_size;
		u8p[0] = *(uint8_t *) iovec[0].iov_base;
		u8p[1] = *(uint8_t *) iovec[1].iov_base;
		request_size = ntohs (request_size);
	}
	if ((request_size + 2) > size)
	  return true;

	/* clear dns request header */
	hev_ring_buffer_read_finish (self->backward_buffer, 2);

	iovec_len = hev_ring_buffer_reading (self->backward_buffer, iovec);
	if (request_size <= iovec[0].iov_len) {
		iovec[0].iov_len = request_size;
		iovec_len = 1;
	} else {
		iovec[1].iov_len = request_size - iovec[0].iov_len;
		iovec_len = 2;
	}

	memset (&mh, 0, sizeof (mh));
	mh.msg_iov = iovec;
	mh.msg_iovlen = iovec_len;
	mh.msg_name = &self->addr;
	mh.msg_namelen = sizeof (self->addr);
	sendmsg (self->cfd, &mh, 0);

	hev_ring_buffer_read_finish (self->backward_buffer, request_size);

	self->step = STEP_CLOSE_SESSION;

	return false;
}

static inline bool
socks5_do_splice (HevSocks5Session *self)
{
	int nonblock = 1;

	/* switch to splice source handler */
	hev_event_source_set_callback (self->source,
				(HevEventSourceFunc) session_source_splice_handler, self, NULL);
	/* add client fd to source */
	ioctl (self->cfd, FIONBIO, (char *) &nonblock);
	self->client_fd = hev_event_source_add_fd (self->source, self->cfd,
				EPOLLIN | EPOLLOUT | EPOLLET);

	return true;
}

static inline void
socks5_close_session (HevSocks5Session *self)
{
	if (self->notify)
	  self->notify (self, self->notify_data);
}

static int
handle_socks5 (HevSocks5Session *self)
{
	bool wait = false;

	switch (self->step) {
	case STEP_NULL:
		self->step = STEP_WRITE_AUTH_METHOD;
	case STEP_WRITE_AUTH_METHOD:
		wait = socks5_write_auth_method (self);
		break;
	case STEP_READ_AUTH_METHOD:
		wait = socks5_read_auth_method (self);
		break;
	case STEP_WRITE_REQUEST:
		wait = socks5_write_request (self);
		break;
	case STEP_READ_RESPONSE:
		wait = socks5_read_response (self);
		break;
	case STEP_FWD_DNS_REQUEST:
		wait = socks5_fwd_dns_request (self);
		break;
	case STEP_FWD_DNS_RESPONSE:
		wait = socks5_fwd_dns_response (self);
		break;
	case STEP_DO_SPLICE:
		wait = socks5_do_splice (self);
		break;
	case STEP_CLOSE_SESSION:
	default:
		return -1;
	}

	return wait ? 1 : 0;
}

static bool
session_source_socks5_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5Session *self = data;
	int wait = -1;

	if ((EPOLLERR | EPOLLHUP) & fd->revents)
	  goto close_session;

	if (fd == self->remote_fd) {
		if (EPOLLIN & fd->revents)
		  self->revents |= REMOTE_IN;
		if (EPOLLOUT & fd->revents)
		  self->revents |= REMOTE_OUT;
	}

	do {
		if (REMOTE_OUT & self->revents) {
			if (!remote_write (self))
			  goto close_session;
		}
		if (REMOTE_IN & self->revents) {
			if (!remote_read (self))
			  goto close_session;
		}

		/* process socks5 protocol */
		wait = handle_socks5 (self);
		if (-1 == wait)
		  goto close_session;
	} while (0 == wait);

	self->idle = false;

	return true;

close_session:
	socks5_close_session (self);

	return true;
}

static bool
session_source_splice_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5Session *self = data;

	if ((EPOLLERR | EPOLLHUP) & fd->revents)
	  goto close_session;

	if (fd == self->client_fd) {
		if (EPOLLIN & fd->revents)
		  self->revents |= CLIENT_IN;
		if (EPOLLOUT & fd->revents)
		  self->revents |= CLIENT_OUT;
	} else {
		if (EPOLLIN & fd->revents)
		  self->revents |= REMOTE_IN;
		if (EPOLLOUT & fd->revents)
		  self->revents |= REMOTE_OUT;
	}

	if (CLIENT_OUT & self->revents) {
		if (!client_write (self))
		  goto close_session;
	}
	if (REMOTE_OUT & self->revents) {
		if (!remote_write (self))
		  goto close_session;
	}
	if (CLIENT_IN & self->revents) {
		if (!client_read (self))
		  goto close_session;
	}
	if (REMOTE_IN & self->revents) {
		if (!remote_read (self))
		  goto close_session;
	}

	self->idle = false;

	return true;

close_session:
	socks5_close_session (self);

	return true;
}


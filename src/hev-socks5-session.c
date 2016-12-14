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

typedef enum _HevSocks5SessionStatus HevSocks5SessionStatus;
typedef void (*HevSocks5SessionHandler) (HevSocks5Session *self);

enum _HevSocks5SessionStatus
{
	HEV_SOCKS5_SESSION_CLIENT_EXCP = (1 << 0),
	HEV_SOCKS5_SESSION_REMOTE_EXCP = (1 << 1),
};

struct _HevSocks5Session
{
	int cfd;
	int rfd;
	unsigned int ref_count;
	bool idle;
	HevSocks5SessionStatus status;
	HevSocks5SessionMode mode;
	HevEventSourceFD *client_fd;
	HevEventSourceFD *remote_fd;
	HevRingBuffer *forward_buffer;
	HevRingBuffer *backward_buffer;
	HevSocks5SessionHandler fhandler;
	HevSocks5SessionHandler bhandler;
	HevEventSource *source;
	HevSocks5SessionCloseNotify notify;
	void *notify_data;
	struct sockaddr_in addr;
};

static bool session_source_socks5_connect_handler (HevEventSourceFD *fd, void *data);
static bool session_source_socks5_dnsfwd_handler (HevEventSourceFD *fd, void *data);
static void session_f_write_connect_request (HevSocks5Session *self);
static void session_f_fwd_tcp_data (HevSocks5Session *self);
static void session_b_read_connect_response (HevSocks5Session *self);
static void session_b_fwd_tcp_data (HevSocks5Session *self);
static void session_f_write_dnsfwd_request (HevSocks5Session *self);
static void session_f_fwd_udp_data (HevSocks5Session *self);
static void session_b_read_dnsfwd_response (HevSocks5Session *self);
static void session_b_fwd_udp_data (HevSocks5Session *self);

HevSocks5Session *
hev_socks5_session_new (int client_fd, int remote_fd, HevSocks5SessionMode mode,
			HevSocks5SessionCloseNotify notify, void *notify_data)
{
	HevSocks5Session *self = HEV_MEMORY_ALLOCATOR_ALLOC (sizeof (HevSocks5Session));
	if (self) {

		self->ref_count = 1;
		self->cfd = client_fd;
		self->rfd = remote_fd;
		self->mode = mode;
		self->idle = false;
		self->status = 0;
		self->client_fd = NULL;
		self->remote_fd = NULL;
		self->forward_buffer = hev_ring_buffer_new (2000);
		self->backward_buffer = hev_ring_buffer_new (2000);
		self->source = NULL;
		self->notify = notify;
		self->notify_data = notify_data;

		if (HEV_SOCKS5_SESSION_MODE_CONNECT == mode) {
			self->fhandler = session_f_write_connect_request;
			self->bhandler = session_b_read_connect_response;
		} else {
			self->fhandler = session_f_fwd_udp_data;
			self->bhandler = session_b_read_dnsfwd_response;

			/* prerecv dns request to avoid new again */
			session_f_write_dnsfwd_request (self);
		}
	}

	return self;
}

HevSocks5Session *
hev_socks5_session_ref (HevSocks5Session *self)
{
	self->ref_count ++;
	return self;
}

void
hev_socks5_session_unref (HevSocks5Session *self)
{
	self->ref_count --;
	if (0 < self->ref_count)
	  return;

	if (HEV_SOCKS5_SESSION_MODE_CONNECT == self->mode)
	  close (self->cfd);
	close (self->rfd);
	hev_ring_buffer_unref (self->forward_buffer);
	hev_ring_buffer_unref (self->backward_buffer);
	if (self->source)
	  hev_event_source_unref (self->source);
	HEV_MEMORY_ALLOCATOR_FREE (self);
}

HevEventSource *
hev_socks5_session_get_source (HevSocks5Session *self)
{
	int nonblock = 1;

	if (self->source)
	  return self->source;

	self->source = hev_event_source_fds_new ();
	if (!self->source)
	  return NULL;


	if (HEV_SOCKS5_SESSION_MODE_CONNECT == self->mode) {
		hev_event_source_set_callback (self->source,
					(HevEventSourceFunc) session_source_socks5_connect_handler,
					self, NULL);

		ioctl (self->cfd, FIONBIO, (char *) &nonblock);
		self->client_fd = hev_event_source_add_fd (self->source, self->cfd,
					EPOLLIN | EPOLLOUT | EPOLLET);
	} else {
		hev_event_source_set_callback (self->source,
					(HevEventSourceFunc) session_source_socks5_dnsfwd_handler,
					self, NULL);
	}

	self->remote_fd = hev_event_source_add_fd (self->source, self->rfd,
				EPOLLIN | EPOLLOUT | EPOLLET);

	return self->source;
}

void
hev_socks5_session_set_idle (HevSocks5Session *self)
{
	self->idle = true;
}

bool
hev_socks5_session_get_idle (HevSocks5Session *self)
{
	return self->idle;
}

HevSocks5SessionMode
hev_socks5_session_get_mode (HevSocks5Session *self)
{
	return self->mode;
}

static inline size_t
iovec2_size (struct iovec *iovec, size_t iovec_len)
{
	switch (iovec_len) {
	case 1:
		return iovec[0].iov_len;
	case 2:
		return iovec[0].iov_len + iovec[1].iov_len;
	}

	return 0;
}

static bool
sync_ring_buffer (HevEventSourceFD *ofd, HevEventSourceFD *ifd, HevRingBuffer *buffer)
{
	struct msghdr mh;
	struct iovec iovec[2];
	size_t iovec_len, data_size;
	ssize_t size;

	iovec_len = hev_ring_buffer_reading (buffer, iovec);
	if (0 == iovec_len) {
		if (ifd)
		  ifd->revents |= EPOLLIN;
		ofd->revents &= ~EPOLLOUT;
		return true;
	}
	data_size = iovec2_size (iovec, iovec_len);

	/* send data */
	memset (&mh, 0, sizeof (mh));
	mh.msg_iov = iovec;
	mh.msg_iovlen = iovec_len;
	size = sendmsg (ofd->fd, &mh, 0);
	if (-1 == size) {
		if (EAGAIN == errno) {
			ofd->revents &= ~EPOLLOUT;
			return false;
		} else {
			ofd->revents |= EPOLLERR;
			return true;
		}
	}

	hev_ring_buffer_read_finish (buffer, size);

	return (size == data_size) ? true : false;
}

static bool
session_source_socks5_connect_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5Session *self = data;

	if ((EPOLLIN & self->client_fd->revents) || (EPOLLOUT & self->remote_fd->revents))
	  self->fhandler (self);

	if ((EPOLLIN & self->remote_fd->revents) || (EPOLLOUT & self->client_fd->revents))
	  self->bhandler (self);

	if ((EPOLLERR | EPOLLHUP) & self->client_fd->revents) {
		self->status |= HEV_SOCKS5_SESSION_CLIENT_EXCP;
		self->client_fd->revents = 0;
	}
	if ((EPOLLERR | EPOLLHUP) & self->remote_fd->revents) {
		self->status |= HEV_SOCKS5_SESSION_REMOTE_EXCP;
		self->remote_fd->revents = 0;
	}
	if (self->status & HEV_SOCKS5_SESSION_CLIENT_EXCP) {
	  if (sync_ring_buffer (self->remote_fd, self->client_fd, self->forward_buffer))
	    goto notify;
	}
	if (self->status & HEV_SOCKS5_SESSION_REMOTE_EXCP) {
	  if (sync_ring_buffer (self->client_fd, self->remote_fd, self->backward_buffer))
	    goto notify;
	}

	self->idle = false;

	return true;

notify:
	self->notify (self, self->notify_data);
	return true;
}

static bool
session_source_socks5_dnsfwd_handler (HevEventSourceFD *fd, void *data)
{
	HevSocks5Session *self = data;

	if (EPOLLOUT & self->remote_fd->revents)
	  self->fhandler (self);

	if (EPOLLIN & self->remote_fd->revents)
	  self->bhandler (self);

	if ((EPOLLERR | EPOLLHUP) & self->remote_fd->revents)
	  goto notify;

	self->idle = false;

	return true;

notify:
	self->notify (self, self->notify_data);
	return true;
}

static ssize_t
recv_to_ring_buffer (HevEventSourceFD *ifd, HevRingBuffer *buffer,
			struct iovec *iovec, size_t *iovec_len)
{
	struct msghdr mh;
	ssize_t size;

	*iovec_len = hev_ring_buffer_writing (buffer, iovec);
	if (0 == *iovec_len) {
		ifd->revents &= ~EPOLLIN;
		return -2;
	}

	/* recv data */
	memset (&mh, 0, sizeof (mh));
	mh.msg_iov = iovec;
	mh.msg_iovlen = *iovec_len;
	size = recvmsg (ifd->fd, &mh, 0);
	if (-1 == size) {
		if (EAGAIN == errno)
		  ifd->revents &= ~EPOLLIN;
		else
		  ifd->revents |= EPOLLERR;
	} else if (0 == size) {
		ifd->revents |= EPOLLHUP;
	}

	return size;
}

static void
session_fwd_data (HevEventSourceFD *ifd, HevEventSourceFD *ofd,
			HevRingBuffer *buffer)
{
	if (EPOLLIN & ifd->revents) {
		struct iovec iovec[2];
		size_t iovec_len;
		ssize_t size = recv_to_ring_buffer (ifd, buffer, iovec, &iovec_len);

		if (-2 == size) {
			ofd->revents |= EPOLLOUT;
		} else if (0 < size) {
			ofd->revents |= EPOLLOUT;
			hev_ring_buffer_write_finish (buffer, size);
		}
	}

	if (EPOLLOUT & ofd->revents)
	  sync_ring_buffer (ofd, ifd, buffer);
}

static void
session_f_write_connect_request (HevSocks5Session *self)
{
	HevEventSourceFD *ifd = self->client_fd;
	HevEventSourceFD *ofd = self->remote_fd;
	HevRingBuffer *buffer = self->forward_buffer;
	struct iovec iovec[2];
	uint8_t *data;
	struct sockaddr_in orig_addr;
	socklen_t orig_addr_len = sizeof (orig_addr);

	/* get original address */
	if (0 != getsockopt (self->cfd, SOL_IP, SO_ORIGINAL_DST,
					(struct sockaddr*) &orig_addr, &orig_addr_len))
	{
		self->client_fd->revents |= EPOLLERR;
		return;
	}

	/* write connect request to ring buffer */
	hev_ring_buffer_writing (buffer, iovec);
	data = iovec[0].iov_base;
	/* auth method */
	data[0] = 0x05;
	data[1] = 0x01;
	data[2] = 0x00;
	/* connect request */
	data[3] = 0x05;
	data[4] = 0x01;
	data[5] = 0x00;
	data[6] = 0x01;
	memcpy (data + 7, &orig_addr.sin_addr, 4);
	memcpy (data + 11, &orig_addr.sin_port, 2);
	hev_ring_buffer_write_finish (buffer, 3 + 10);

	sync_ring_buffer (ofd, ifd, buffer);

	self->fhandler = session_f_fwd_tcp_data;
}

static void
session_f_fwd_tcp_data (HevSocks5Session *self)
{
	session_fwd_data (self->client_fd, self->remote_fd, self->forward_buffer);
}

static void
session_b_read_connect_response (HevSocks5Session *self)
{
	HevEventSourceFD *ifd = self->remote_fd;
	HevEventSourceFD *ofd = self->client_fd;
	HevRingBuffer *buffer = self->backward_buffer;
	struct iovec iovec[2];
	size_t iovec_len, size;
	uint8_t *data;

	if (EPOLLIN & ifd->revents) {
		struct iovec iovec[2];
		size_t iovec_len;
		ssize_t size = recv_to_ring_buffer (ifd, buffer, iovec, &iovec_len);

		if (0 < size)
		  hev_ring_buffer_write_finish (buffer, size);
	}

	if (EPOLLOUT & ofd->revents)
	  ofd->revents &= ~EPOLLOUT;

	iovec_len = hev_ring_buffer_reading (buffer, iovec);
	size = iovec2_size (iovec, iovec_len);
	data = iovec[0].iov_base;
	/* check auth method */
	if (2 > size)
	  return;
	if ((0x05 != data[0]) || (0x00 != data[1])) {
		ifd->revents |= EPOLLERR;
		return;
	}
	/* check response */
	if (6 > size)
	  return;
	if ((0x05 != data[2]) || (0x00 != data[3]) || (0x01 != data[5])) {
		ifd->revents |= EPOLLERR;
		return;
	}
	if (10 > size)
	  return;
	/* clear response in buffer */
	hev_ring_buffer_read_finish (buffer, 2 + 10);

	ifd->revents |= EPOLLIN;
	ofd->revents |= EPOLLOUT;
	self->bhandler = session_b_fwd_tcp_data;
}

static void
session_b_fwd_tcp_data (HevSocks5Session *self)
{
	session_fwd_data (self->remote_fd, self->client_fd, self->backward_buffer);
}

static void
session_f_write_dnsfwd_request (HevSocks5Session *self)
{
	HevRingBuffer *buffer = self->forward_buffer;
	struct iovec iovec[2];
	size_t iovec_len;
	uint8_t *data;
	struct msghdr mh;
	ssize_t size;

	/* write dnsfwd request to ring buffer */
	hev_ring_buffer_writing (buffer, iovec);
	data = iovec[0].iov_base;
	/* auth method */
	data[0] = 0x05;
	data[1] = 0x01;
	data[2] = 0x00;
	/* dnsfwd request */
	data[3] = 0x05;
	data[4] = 0x04;
	data[5] = 0x00;
	data[6] = 0x01;
	hev_ring_buffer_write_finish (buffer, 3 + 10 + 2);

	iovec_len = hev_ring_buffer_writing (buffer, iovec);
	memset (&mh, 0, sizeof (mh));
	mh.msg_iov = iovec;
	mh.msg_iovlen = iovec_len;
	mh.msg_name = &self->addr;
	mh.msg_namelen = sizeof (self->addr);
	size = recvmsg (self->cfd, &mh, 0);
	if (0 >= size) {
		self->remote_fd->revents |= EPOLLERR;
		return;
	} else {
		uint16_t *req_size = (uint16_t *)(data + 3 + 10);
		*req_size = htons (size);
		hev_ring_buffer_write_finish (buffer, size);
	}
}

static void
session_f_fwd_udp_data (HevSocks5Session *self)
{
	HevEventSourceFD *ofd = self->remote_fd;
	HevRingBuffer *buffer = self->forward_buffer;

	if (EPOLLOUT & ofd->revents)
	  sync_ring_buffer (ofd, NULL, buffer);
}

static void
session_b_read_dnsfwd_response (HevSocks5Session *self)
{
	HevEventSourceFD *ifd = self->remote_fd;
	HevRingBuffer *buffer = self->backward_buffer;
	struct iovec iovec[2];
	size_t iovec_len, size;
	uint8_t *data;

	if (EPOLLIN & ifd->revents) {
		struct iovec iovec[2];
		size_t iovec_len;
		ssize_t size = recv_to_ring_buffer (ifd, buffer, iovec, &iovec_len);

		if (0 < size)
		  hev_ring_buffer_write_finish (buffer, size);
	}

	iovec_len = hev_ring_buffer_reading (buffer, iovec);
	size = iovec2_size (iovec, iovec_len);
	data = iovec[0].iov_base;
	/* check auth method */
	if (2 > size)
	  return;
	if ((0x05 != data[0]) || (0x00 != data[1])) {
		ifd->revents |= EPOLLERR;
		return;
	}
	/* check response */
	if (6 > size)
	  return;
	if ((0x05 != data[2]) || (0x00 != data[3]) || (0x01 != data[5])) {
		ifd->revents |= EPOLLERR;
		return;
	}
	if (10 > size)
	  return;
	/* clear response in buffer */
	hev_ring_buffer_read_finish (buffer, 2 + 10);

	ifd->revents |= EPOLLIN;
	self->bhandler = session_b_fwd_udp_data;
}

static void
session_b_fwd_udp_data (HevSocks5Session *self)
{
	HevEventSourceFD *ifd = self->remote_fd;
	HevRingBuffer *buffer = self->backward_buffer;
	struct iovec iovec[2];
	size_t iovec_len, size;
	struct msghdr mh;
	uint16_t res_size;

	if (EPOLLIN & ifd->revents) {
		struct iovec iovec[2];
		size_t iovec_len;
		ssize_t size = recv_to_ring_buffer (ifd, buffer, iovec, &iovec_len);

		if (0 < size)
		  hev_ring_buffer_write_finish (buffer, size);
	}

	iovec_len = hev_ring_buffer_reading (buffer, iovec);
	size = iovec2_size (iovec, iovec_len);
	/* check dns response length header */
	if (2 > size)
	  return;
	/* check dns response length */
	res_size = ntohs (*(uint16_t *) iovec[0].iov_base);
	if ((res_size + 2) > size)
	  return;
	/* clear dns response length header */
	hev_ring_buffer_read_finish (buffer, 2);

	iovec_len = hev_ring_buffer_reading (buffer, iovec);

	memset (&mh, 0, sizeof (mh));
	mh.msg_iov = iovec;
	mh.msg_iovlen = iovec_len;
	mh.msg_name = &self->addr;
	mh.msg_namelen = sizeof (self->addr);
	sendmsg (self->cfd, &mh, 0);

	hev_ring_buffer_read_finish (buffer, res_size);

	/* close session */
	ifd->revents |= EPOLLHUP;
}


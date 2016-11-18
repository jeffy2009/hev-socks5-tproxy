/*
 ============================================================================
 Name        : hev-socks5-session.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 session
 ============================================================================
 */

#ifndef __HEV_SOCKS5_SESSION_H__
#define __HEV_SOCKS5_SESSION_H__

#include <hev-lib.h>

enum _HevSocks5SessionMode
{
	HEV_SOCKS5_SESSION_MODE_CONNECT,
	HEV_SOCKS5_SESSION_MODE_DNS_FWD,
};

typedef struct _HevSocks5Session HevSocks5Session;
typedef enum _HevSocks5SessionMode HevSocks5SessionMode;
typedef void (*HevSocks5SessionCloseNotify) (HevSocks5Session *self, void *data);

HevSocks5Session * hev_socks5_session_new (int client_fd, int remote_fd,
			HevSocks5SessionMode mode, HevSocks5SessionCloseNotify notify,
			void *notify_data);

HevSocks5Session * hev_socks5_session_ref (HevSocks5Session *self);
void hev_socks5_session_unref (HevSocks5Session *self);

HevEventSource * hev_socks5_session_get_source (HevSocks5Session *self);

void hev_socks5_session_set_idle (HevSocks5Session *self);
bool hev_socks5_session_get_idle (HevSocks5Session *self);

HevSocks5SessionMode hev_socks5_session_get_mode (HevSocks5Session *self);

#endif /* __HEV_SOCKS5_SESSION_H__ */


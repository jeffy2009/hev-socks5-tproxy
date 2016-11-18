/*
 ============================================================================
 Name        : hev-socks5-tproxy.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2014 everyone.
 Description : Socks5 transparent proxy
 ============================================================================
 */

#ifndef __HEV_SOCKS5_TPROXY_H__
#define __HEV_SOCKS5_TPROXY_H__

#include <hev-lib.h>

typedef struct _HevSocks5TProxy HevSocks5TProxy;

HevSocks5TProxy * hev_socks5_tproxy_new (HevEventLoop *loop,
			const char *laddr, unsigned short lport,
			const char *ldaddr, unsigned short ldport,
			const char *saddr, unsigned short sport);

HevSocks5TProxy * hev_socks5_tproxy_ref (HevSocks5TProxy *self);
void hev_socks5_tproxy_unref (HevSocks5TProxy *self);

#endif /* __HEV_SOCKS5_TPROXY_H__ */


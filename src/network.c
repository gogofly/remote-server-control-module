/******************************************************************************
 * Copyright (c) 2014, gogofly.net (ginozhang@vip.qq.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 * *******************************************************************************/

/*
 * network function. communicate with remote server
 * */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include "ngx_http_remote_srv_control_module.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <memory.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>


#include "network.h"

ngx_int_t ngx_udp_connect(ngx_udp_connection_t *uc);


#define REAL_FREE_SOCKET_BUFFER() do{ \
            ngx_pfree(r->pool, pBuf); \
}while(0)


#define FREE_SOCKET_BUFFER() do{ \
        if (pBuf != NULL) { \
            REAL_FREE_SOCKET_BUFFER(); \
            pBuf = NULL;  \
        } \
}while(0)

#define FREE_SOCKET_BUFFER_RETURN() do{ \
    FREE_SOCKET_BUFFER(); \
    /*return DEFENSE_RESULT_OK;*/ return REMOTESRV_FUN_RETURN_ERROR; \
}while(0)

static void recv_handler(ngx_event_t *ev) {
	ngx_http_request_t *r;
	ngx_connection_t *c;
	ngx_http_remotesrv_ctx_t *ctx;
    int normal_resp_pkg_len = 1023;
    uint8_t resp_buf[1024];
    int actual_resp_pkg_len;

	c = ev->data;
	r = c->data;
	ctx = ngx_http_get_module_ctx(r, ngx_http_remote_srv_control_module);
    if(!ctx)
    {
        ngx_close_connection(c);
        if(r->main->count>=2)
        {
            r->main->count--; 
        }
        ngx_http_finalize_request(r, NGX_ERROR);
        
        return;
    }
    ctx->remotesrv_defense_result=DEFENSE_RESULT_OK;
    ctx->recv=1;
    actual_resp_pkg_len = ngx_recv(c, resp_buf, normal_resp_pkg_len);
    if(ev->timedout) 
    {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "recv_handler. timeout");
    }
    else if(actual_resp_pkg_len <= 0) 
    {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "recv_handler. recv error. code: %d", actual_resp_pkg_len);
    }
    else
    {
        //unpack
        /* should check seq
        if (head.uiSeq != ctx->uiSeq) {
            goto END_recv_handler;
        }*/
        ctx->remotesrv_defense_result='s'==resp_buf[0]?DEFENSE_RESULT_NOTOK:DEFENSE_RESULT_OK;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "recv_handler. recvfrom got [%d] bytes. result: %d", actual_resp_pkg_len, ctx->remotesrv_defense_result);

//END_recv_handler:
    ngx_close_connection(c);
    //report_log_no_cnt_inc(CNT_NGX_FREE_CONNECT);
    if(r->main->count<2)
    {
    }
    else{
        r->main->count--;
    }
#if defined(nginx_version) && ( nginx_version >= 1004000 )
    ngx_http_process_request  (r); 
#endif
    return ;
}

int conn_send_udp(ngx_http_request_t *r, void* ptr_req_buf, int req_buf_len
        , ngx_str_t remotesrv_ip, ngx_int_t remotesrv_port, ngx_int_t timeout)
{
    ssize_t                n;
    ngx_udp_connection_t  *uc;
    struct sockaddr_in* psrvaddr;

    uc = (ngx_udp_connection_t *)ngx_pcalloc(r->pool, sizeof(ngx_udp_connection_t));
    if (uc == NULL) {
        return REMOTESRV_FUN_RETURN_ERROR;
    }
    psrvaddr = (struct sockaddr_in *)ngx_pcalloc(r->pool, sizeof(struct sockaddr_in));
    if (psrvaddr == NULL) {
        ngx_pfree(r->pool, uc);
        return REMOTESRV_FUN_RETURN_ERROR;
    }

    psrvaddr->sin_family = AF_INET;
    psrvaddr->sin_port = htons(remotesrv_port);
    inet_pton(AF_INET, remotesrv_ip.data, &(psrvaddr->sin_addr));
    uc->sockaddr = (struct sockaddr*)psrvaddr;
    uc->socklen = sizeof(struct sockaddr_in );

    if(ngx_udp_connect(uc) != NGX_OK) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "__mydebug. ngx_udp_connect error");
        ngx_pfree(r->pool, uc);
        ngx_pfree(r->pool, psrvaddr);
        return REMOTESRV_FUN_RETURN_ERROR;
    }
    uc->connection->data = r;
    uc->connection->read->handler = recv_handler;
    uc->connection->read->resolver = 0;
    if (ngx_handle_read_event(uc->connection->read, 0) != NGX_OK) {
        goto ENDERR_conn_send_udp;
    }
    //send
    n = ngx_send(uc->connection, ptr_req_buf, req_buf_len);
    if (n == -1) {
        goto ENDERR_conn_send_udp;
    }

    if ((size_t) n != (size_t) req_buf_len) {
        ngx_log_error(NGX_LOG_CRIT, &uc->log, 0, "send() incomplete");
        goto ENDERR_conn_send_udp;
    }

	r->main->count++;
	//if (mlcf->timeout != NGX_CONF_UNSET_MSEC)
    {
		ngx_add_timer(uc->connection->read, timeout);
    }
    return REMOTESRV_FUN_RETURN_NORMAL;

ENDERR_conn_send_udp:
    if(uc->connection) 
    {
        ngx_close_connection(uc->connection);
        //report_log_no_cnt_inc(CNT_NGX_FREE_CONNECT);
    } 
    ngx_pfree(r->pool, uc);
    ngx_pfree(r->pool, psrvaddr);
    return REMOTESRV_FUN_RETURN_ERROR;
}

int send_to_remote_srv(ngx_http_request_t *r, u_char *header_buf,  uint32_t header_buf_len
        , u_char *body_buf, int body_buf_len
        , ngx_str_t remotesrv_ip, ngx_int_t remotesrv_port, ngx_int_t timeout)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "__mydebug_remotesrv. send_to_remote_srv is called!");
    if (!r || !header_buf) {
        return REMOTESRV_FUN_RETURN_ERROR; 
    }
    //tlv PKG: client_ip, header, body
    //r->connection->addr_text.data
    int ret = conn_send_udp(r, header_buf, header_buf_len, remotesrv_ip, remotesrv_port, timeout);	
    if (ret==REMOTESRV_FUN_RETURN_ERROR) {
        //FREE_SOCKET_BUFFER_RETURN();
    } 
    return REMOTESRV_FUN_RETURN_NORMAL;
}

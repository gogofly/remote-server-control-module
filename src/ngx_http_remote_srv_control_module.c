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
 * block current request and Concurrently deal other request
 * */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

#include "ngx_http_remote_srv_control_module.h"
#include "network.h"

#define NGX_REMOTESRV_NEXT NGX_OK
#define NGX_REMOTESRV_HOLD NGX_AGAIN

#define NGX_REMOTESRV_OK NGX_OK
#define NGX_REMOTESRV_NOT_OK NGX_DECLINED

#define MAX_REQ_HEADER_BUF_LEN 			8*1024
#define MAX_REQ_BODY_BUF_LEN			8*1024*1024
#define MAX_RESP_HEADER_BUF_LEN			8*1024
#define MAX_RESP_BODY_BUF_LEN			36*1024

/* NB: ms */
#define REMOTESRV_DEFAULT_TIMEOUT 20
#define REMOTESRV_DEFAULT_REMOTESRV_IP "127.0.0.1"
#define REMOTESRV_DEFAULT_REMOTESRV_PORT 8888
typedef struct {
    ngx_flag_t remotesrv_module;
	ngx_int_t timeout;
    ngx_str_t remotesrv_ip;
    ngx_int_t remotesrv_port;
} ngx_http_remotesrv_main_conf_t;

static void *ngx_http_remotesrv_create_main_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_remotesrv_init(ngx_conf_t *cf);

//static void* ngx_http_remotesrv_create_loc_conf(ngx_conf_t *cf);

static ngx_command_t ngx_http_remotesrv_commands[] = {
    {   
        ngx_string("remotesrv_module"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_remotesrv_main_conf_t, remotesrv_module),
        NULL
    },  
    {   
        ngx_string("remotesrv_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_remotesrv_main_conf_t, timeout),
        NULL
    },
    { 
        ngx_string("remotesrv_ip"),

        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        0,
        offsetof(ngx_http_remotesrv_main_conf_t, remotesrv_ip),
        NULL 
    },
    { 
        ngx_string("remotesrv_port"),

        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        0,
        offsetof(ngx_http_remotesrv_main_conf_t, remotesrv_port),
        NULL 
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_remotesrv_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_remotesrv_init,           /* postconfiguration */

    ngx_http_remotesrv_create_main_conf,/* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL, //ngx_http_remotesrv_create_loc_conf,                           /* create location configuration */
    NULL                            /* merge location configuration */
};

ngx_module_t ngx_http_remote_srv_control_module = {
    NGX_MODULE_V1,
    &ngx_http_remotesrv_module_ctx,    /* module context */
    ngx_http_remotesrv_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static void ngx_http_remotesrv_post_read_request_body(ngx_http_request_t *r)
{
    ngx_http_remotesrv_ctx_t  *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_remote_srv_control_module);
    ctx->ready = 1;
    r->main->count--;
    if (ctx->wait_for_body) {
        ctx->wait_for_body = 0;
        ngx_http_core_run_phases(r);
    }
}

ngx_int_t	ngx_http_conn_send_mssrv( ngx_http_request_t	 *r)
{
    ngx_http_remotesrv_ctx_t	*ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_remote_srv_control_module);
    if (ctx == NULL) {
        return REMOTESRV_FUN_RETURN_ERROR; 
    }
    uint32_t buffer_len = sizeof(char) * MAX_REQ_HEADER_BUF_LEN;
    u_char *header_buf = (u_char*)ngx_pcalloc(r->pool, buffer_len);
    if (header_buf == NULL) {
        return REMOTESRV_FUN_RETURN_ERROR;
    }

    uint32_t header_buf_len = 0;
    uint32_t tmp_cpy_len = 0;
    if(buffer_len-header_buf_len>=r->request_line.len)
    { 
        tmp_cpy_len = r->request_line.len;
    } else {
        tmp_cpy_len = buffer_len-header_buf_len; 
    }

    memcpy ((char*)header_buf+header_buf_len, r->request_line.data, tmp_cpy_len);
    header_buf_len += tmp_cpy_len;

    if (buffer_len-header_buf_len >= 2) {
        memcpy ((char*)header_buf+header_buf_len, "\r\n", 2);     
    }
    header_buf_len += 2;

    ngx_list_part_t	    *part;
    ngx_table_elt_t	    *h;
    uint32_t		     i;
    part = &r->headers_in.headers.part;
    h = part->elts;
    // this check may be removed, as it shouldn't be needed anymore !
    for (i = 0; 1 ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) 
                break;
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (buffer_len - header_buf_len >= h[i].key.len) {
            memcpy((char*)header_buf+header_buf_len, h[i].key.data, h[i].key.len); 
            header_buf_len += h[i].key.len;
        } else {
            memcpy((char*)header_buf+header_buf_len, h[i].key.data, buffer_len - header_buf_len); 
            header_buf_len += buffer_len - header_buf_len;
        }
        if (buffer_len - header_buf_len >= 1) {
            memcpy((char*)header_buf+header_buf_len, ":", 1); 
            header_buf_len++;
        }
        if (buffer_len - header_buf_len >= h[i].value.len) {
            memcpy((char*)header_buf+header_buf_len, h[i].value.data, h[i].value.len);
            header_buf_len += h[i].value.len;
        } else {
            memcpy((char*)header_buf+header_buf_len, h[i].value.data,buffer_len - header_buf_len);
            header_buf_len += buffer_len - header_buf_len;
        }
        if (buffer_len - header_buf_len >= 2) {
            memcpy((char*)header_buf+header_buf_len, "\r\n", 2);
            header_buf_len += 2;
        }
    }
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "__mydebug_remotesrv. len: %d header: \n%s", header_buf_len, header_buf);

    u_char *body_buf = NULL;
    int body_buf_len = 0;
    if (r->method == NGX_HTTP_POST) {

        uint32_t content_length = 0;
        ngx_table_elt_t *content_length_table_elt = r->headers_in.content_length;
        if (content_length_table_elt == NULL || content_length_table_elt->value.data == NULL) {
            return REMOTESRV_FUN_RETURN_ERROR;
        }
        content_length = atoi((char*)(content_length_table_elt->value.data));

        if (ctx == NULL) {
            return REMOTESRV_FUN_RETURN_ERROR; 
        }

        if (content_length > MAX_REQ_BODY_BUF_LEN) {
            return REMOTESRV_FUN_RETURN_ERROR;
        }
        //http post
        if (r->request_body && r->request_body->bufs) {
            body_buf = (u_char*)ngx_pcalloc(r->pool, content_length+1);
            if (body_buf == NULL) {
                return REMOTESRV_FUN_RETURN_ERROR; 
            }
            ngx_chain_t *chain_link=r->request_body->bufs;
            for (; chain_link; chain_link = chain_link->next)
            {
                if(chain_link->buf)
                {
                    if(chain_link->buf->pos)
                    {
                        uint32_t iLen=chain_link->buf->last - chain_link->buf->pos;
                        if(iLen <= content_length-body_buf_len)
                        {
                            memcpy(body_buf, chain_link->buf->pos, iLen);
                            body_buf_len += iLen;
                            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "__mydebug_remotesrv. len: %d http post: %s", iLen, body_buf);
                        } else {
                            memcpy(body_buf, chain_link->buf->pos, content_length-body_buf_len); 
                            body_buf_len += content_length-body_buf_len;
                        }
                    }
                    else if(chain_link->buf->file)
                    {
                        ssize_t n = ngx_read_file(chain_link->buf->file, body_buf + body_buf_len, content_length-body_buf_len, 0);
                        body_buf_len += n;
                    }
                }
            }
        }
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "post body buf:[%s], len:[%d]", body_buf, body_buf_len);
    } else {
        body_buf = NULL;
        body_buf_len = 0; 
    }

    //pack data
    //send header,body data to remote server
    int check_result = REMOTESRV_FUN_RETURN_ERROR;
    ngx_http_remotesrv_main_conf_t *mmcf;
    mmcf = ngx_http_get_module_main_conf(r, ngx_http_remote_srv_control_module);
    if(!mmcf)
    {
        return check_result;
    }
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "__mydebug_remotesrv. remotesrv_module: %d remotesrv_ip: %s remotesrv_port: %d timeout: %d"
            , mmcf->remotesrv_module, mmcf->remotesrv_ip.data
            , mmcf->remotesrv_port, mmcf->timeout
            );
    check_result = send_to_remote_srv(r, header_buf, header_buf_len, body_buf, body_buf_len
            , mmcf->remotesrv_ip, mmcf->remotesrv_port, mmcf->timeout);
    return check_result;
}

ngx_int_t ngx_http_remotesrv_handler(ngx_http_request_t *r) {
    ngx_http_remotesrv_ctx_t	*ctx;
    ngx_int_t			rc;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "status: unkown. uri: %V args: %V r: %p r->main: %p r->count: %d", &r->uri, &r->args, r, r->main, r->count);

#if defined(nginx_version) && ( nginx_version < 1004000 )
    return NGX_REMOTESRV_NEXT;
#endif

    if(r != r->main )
    {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "__mydebug. r != r->main ");
        return NGX_REMOTESRV_NEXT;
    }
    ctx = ngx_http_get_module_ctx(r, ngx_http_remote_srv_control_module);
    if (ctx && ctx->recv)
    {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "status: over. uri: %V args: %V defense result: %d r: %p r->main: %p r->count: %d", &r->uri, &r->args, ctx->remotesrv_defense_result, r, r->main, r->count);
        if (ctx->remotesrv_defense_result == DEFENSE_RESULT_NOTOK) {
            return NGX_HTTP_NOT_IMPLEMENTED; 
        } else {
            return NGX_REMOTESRV_NEXT;
        }
    }
    if (ctx && ctx->wait_for_body) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "status: wait_for_body. uri: %V. args: %V r: %p r->main: %p r->count: %d", &r->uri, &r->args, r, r->main, r->count);
        return NGX_REMOTESRV_HOLD;
    }
    if (ctx && ctx->send) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "status: wait_for_remotesrvsrv. uri: %V. args: %V r: %p r->main: %p r->count: %d", &r->uri, &r->args, r, r->main, r->count);
        return NGX_REMOTESRV_HOLD;
    }
    if (!ctx) 
    {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_remotesrv_ctx_t));
        if (ctx == NULL)
        {
            return NGX_REMOTESRV_NEXT;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_remote_srv_control_module);
        ctx->wait_for_body = 0;
        ctx->ready = 0;
        ctx->send = 0;
        ctx->recv = 0;
        //post
        if  ((r->method == NGX_HTTP_POST || r->method == NGX_HTTP_PUT) 
                && !ctx->ready) {
            rc = ngx_http_read_client_request_body(r, ngx_http_remotesrv_post_read_request_body);
            if (rc == NGX_AGAIN) {
                ctx->wait_for_body = 1;
                return NGX_REMOTESRV_HOLD;
            }
            else if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return NGX_REMOTESRV_NEXT;
            }
        }
        else
        {
            ctx->ready = 1;
        }

    }
    if (ctx && ctx->ready && !ctx->send) {
        ctx->send = 1;
        rc=ngx_http_conn_send_mssrv(r);
        if(rc == REMOTESRV_FUN_RETURN_ERROR)
        {
            return NGX_REMOTESRV_NEXT;
        }
        else if(rc == REMOTESRV_FUN_RETURN_NOTOK)
        {
            return NGX_HTTP_NOT_IMPLEMENTED; 
        }
    }
    return NGX_REMOTESRV_HOLD;
}
#if 0
static void* ngx_http_remotesrv_create_loc_conf(ngx_conf_t *cf)
{
    return NULL;
}
#endif 
static ngx_int_t ngx_http_remotesrv_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_http_remotesrv_main_conf_t *mmcf;
    mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_remote_srv_control_module);

    if (mmcf && mmcf->remotesrv_module == 0) {
        //remotesrv disabled
        return NGX_OK;
    }
    if (mmcf->remotesrv_ip.len == 0) {
        ngx_str_set(&mmcf->remotesrv_ip, REMOTESRV_DEFAULT_REMOTESRV_IP);
    }
    if (mmcf->timeout == NGX_CONF_UNSET_UINT)
    {
        mmcf->timeout = REMOTESRV_DEFAULT_TIMEOUT; 
    }
    if (mmcf->remotesrv_port == NGX_CONF_UNSET_UINT)
    {
        mmcf->remotesrv_port =REMOTESRV_DEFAULT_REMOTESRV_PORT; 
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_remotesrv_handler;

    return NGX_OK;
}
static void *ngx_http_remotesrv_create_main_conf(ngx_conf_t *cf) {
    ngx_http_remotesrv_main_conf_t *mmcf;
    mmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_remotesrv_main_conf_t));
    if (mmcf == NULL) {
        return NULL;
    }

    mmcf->remotesrv_module = NGX_CONF_UNSET;
    mmcf->timeout = NGX_CONF_UNSET_UINT; 
    mmcf->remotesrv_port = NGX_CONF_UNSET_UINT; 
    return mmcf;

}

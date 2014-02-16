
#ifndef  NETWORK_INC
#define  NETWORK_INC
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

int send_to_remote_srv(ngx_http_request_t *r, u_char *header_buf,  uint32_t header_buf_len
        , u_char *body_buf, int body_buf_len
        , ngx_str_t remotesrv_ip, ngx_int_t remotesrv_port, ngx_int_t timeout);

#endif   /* ----- #ifndef NETWORK_INC  ----- */


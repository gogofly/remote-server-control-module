
#ifndef  NGX_HTTP_REMOTE_SRV_CONTROL_MODULE_INC
#define  NGX_HTTP_REMOTE_SRV_CONTROL_MODULE_INC
#include <ngx_config.h>
#include <ngx_core.h>
#include <ucontext.h>
#include <ngx_http.h>
#include <nginx.h>

#define REMOTESRV_FUN_RETURN_OK DEFENSE_RESULT_OK
#define REMOTESRV_FUN_RETURN_NOTOK DEFENSE_RESULT_NOTOK
#define REMOTESRV_FUN_RETURN_ERROR (DEFENSE_RESULT_NOTOK+1)
#define REMOTESRV_FUN_RETURN_NORMAL (REMOTESRV_FUN_RETURN_ERROR+1)

typedef struct
{
    /* state */
    ngx_flag_t	wait_for_body:1;
    ngx_flag_t	ready:1;
    ngx_flag_t	send:1;  //send to remotesrvsrv
    ngx_flag_t	recv:1;  //recv data from remotesrvsrv

	/* current handler contexts: wake & return */
	int timedout;
    int done;

    int remotesrv_defense_result;

	uint32_t uiSeq;					//seq
} ngx_http_remotesrv_ctx_t;
 
#define DEFENSE_RESULT_OK					1		//
#define DEFENSE_RESULT_NOTOK 				2		//

extern ngx_module_t ngx_http_remote_srv_control_module;

#endif   /* ----- #ifndef NGX_HTTP_REMOTE_SRV_CONTROL_MODULE_INC  ----- */


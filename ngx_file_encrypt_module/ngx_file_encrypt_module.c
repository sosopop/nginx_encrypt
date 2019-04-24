#include "ngx_core.h"
#include "ngx_string.h"
#include "ngx_buf.h"
#include "ngx_module.h"
#include "ngx_conf_file.h"
#include "ngx_http.h"
#include "ngx_http_request.h"
#include "ngx_http_config.h"
#include "ngx_http_core_module.h"

// 返回值如NGX_HTTP_OK（200）、NGX_HTTP_NOT_FOUND（404）、NGX_HTTP_INTERNAL_SERVER_ERROR（500）、NGX_OK（0）、NGX_ERROR（-1）等
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)
{
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
        return NGX_HTTP_NOT_ALLOWED;

    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK)
        return rc;

    ngx_str_t type = ngx_string("text/plain");
    ngx_str_t response = ngx_string("Hello World!\n");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = response.len;
    r->headers_out.content_type = type;

    /* 发送HTTP响应时需要执行发送HTTP头部（和响应行）和发送HTTP包体两步操作，此为第一步
       该函数会首先调用所有的HTTP过滤模块共同处理r->headers_out中定义的HTTP响应头部，全部处理完毕后才会序列化为TCP字节流发送到客户端 */
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        return rc;

    ngx_buf_t *b;
    b = ngx_create_temp_buf(r->pool, response.len);
    if (b == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_memcpy(b->pos, response.data, response.len);
    b->last = b->pos + response.len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);  // 发送HTTP响应包体
}

static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mytest_handler;  // HTTP框架接收完HTTP请求的头部后，将调用该函数

    return NGX_CONF_OK;
}

static ngx_command_t ngx_file_encrypt_commands[] = {
    {ngx_string("tryconf"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
        NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS, ngx_http_mytest, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},
    ngx_null_command
};

static ngx_http_module_t ngx_file_encrypt_module_ctx = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_file_encrypt_module = {
    NGX_MODULE_V1,
    &ngx_file_encrypt_module_ctx,
    ngx_file_encrypt_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
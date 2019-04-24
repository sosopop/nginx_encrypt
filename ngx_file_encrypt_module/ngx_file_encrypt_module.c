
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t     encrypt_key;
} ngx_file_encrypt_conf_t;


typedef struct {
} ngx_file_encrypt_ctx_t;


static void *ngx_file_encrypt_create_conf(ngx_conf_t *cf);
static char *ngx_file_encrypt_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_file_encrypt_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_file_encrypt_commands[] = {

    { ngx_string("encrypt_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_file_encrypt_conf_t, encrypt_key),
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_file_encrypt_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_file_encrypt_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_file_encrypt_create_conf,         /* create location configuration */
    ngx_file_encrypt_merge_conf           /* merge location configuration */
};


ngx_module_t  ngx_file_encrypt_module = {
    NGX_MODULE_V1,
    &ngx_file_encrypt_module_ctx,  /* module context */
    ngx_file_encrypt_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_encrypt_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_uint_t                 last;
    ngx_chain_t               *cl;
    ngx_http_request_t        *sr;
    ngx_file_encrypt_ctx_t   *ctx;
    ngx_file_encrypt_conf_t  *conf;

    if (in == NULL || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_file_encrypt_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_file_encrypt_module);
/*
    if (!ctx->before_body_sent) {
        ctx->before_body_sent = 1;

        if (conf->before_body.len) {
            if (ngx_http_subrequest(r, &conf->before_body, NULL, &sr, NULL, 0)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    if (conf->after_body.len == 0) {
        ngx_http_set_ctx(r, NULL, ngx_file_encrypt_module);
        return ngx_http_next_body_filter(r, in);
    }

    last = 0;
*/
    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            last = 1;
        }
    }

    rc = ngx_http_next_body_filter(r, in);

    if (rc == NGX_ERROR || !last || conf->after_body.len == 0) {
        return rc;
    }

    if (ngx_http_subrequest(r, &conf->after_body, NULL, &sr, NULL, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, NULL, ngx_file_encrypt_module);

    return ngx_http_send_special(r, NGX_HTTP_LAST);
}


static ngx_int_t
ngx_file_encrypt_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_encrypt_body_filter;
    return NGX_OK;
}


static void *
ngx_file_encrypt_create_conf(ngx_conf_t *cf)
{
    ngx_file_encrypt_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_file_encrypt_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->before_body = { 0, NULL };
     *     conf->after_body = { 0, NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    return conf;
}


static char *
ngx_file_encrypt_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_file_encrypt_conf_t *prev = parent;
    ngx_file_encrypt_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->encrypt_key, prev->encrypt_key, "test");

    return NGX_CONF_OK;
}

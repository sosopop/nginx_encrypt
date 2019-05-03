
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct
{
    ngx_str_t encrypt_key;
} ngx_file_encrypt_conf_t;

typedef struct
{
    ngx_str_t encrypt_key;
    ngx_int_t crypted;
} ngx_file_encrypt_ctx_t;

static void *ngx_file_encrypt_create_conf(ngx_conf_t *cf);
static char *ngx_file_encrypt_merge_conf(ngx_conf_t *cf, void *parent,
                                         void *child);
static ngx_int_t ngx_file_encrypt_filter_init(ngx_conf_t *cf);

static ngx_command_t ngx_file_encrypt_commands[] = {

    {ngx_string("encrypt_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_file_encrypt_conf_t, encrypt_key),
     NULL},
    ngx_null_command};

static ngx_http_module_t ngx_file_encrypt_module_ctx = {
    NULL,                         /* preconfiguration */
    ngx_file_encrypt_filter_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_file_encrypt_create_conf, /* create location configuration */
    ngx_file_encrypt_merge_conf   /* merge location configuration */
};

ngx_module_t ngx_file_encrypt_module = {
    NGX_MODULE_V1,
    &ngx_file_encrypt_module_ctx, /* module context */
    ngx_file_encrypt_commands,    /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t
ngx_http_encrypt_header_filter(ngx_http_request_t *r)
{
    r->main_filter_need_in_memory = 1;
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_encrypt_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t rc;
    ngx_uint_t last;
    ngx_chain_t *cl = in;
    ngx_http_request_t *sr;
    ngx_file_encrypt_ctx_t *ctx;
    ngx_file_encrypt_conf_t *conf;
    off_t clen;
    off_t coff;
    u_char *buf_pos;

    if (in == NULL || r->header_only)
    {
        return ngx_http_next_body_filter(r, in);
    }

    //ctx = ngx_http_get_module_ctx(r, ngx_file_encrypt_module);

    //if (ctx == NULL) {
    //return ngx_http_next_body_filter(r, in);
    //}
    conf = ngx_http_get_module_loc_conf(r, ngx_file_encrypt_module);

    while(cl) {
        if (cl->buf->in_file &&
            ngx_buf_in_memory(cl->buf) &&
            cl->buf->file_last - cl->buf->file_pos == cl->buf->last - cl->buf->pos)
        {
            off_t file_pos = cl->buf->file_pos;
            off_t buf_size = cl->buf->last - cl->buf->pos;
            ngx_int_t i = file_pos;
            u_char* buf = cl->buf->pos;
            ngx_int_t key_len = conf->encrypt_key.len;
            u_char* key = conf->encrypt_key.data;
            
            for (i = 0; i < buf_size; i++)
            {
                int c = file_pos + i + 1;
                c = c ^ (c << 1) ^ (c << 2) ^ (c << 4) ^ (c << 6) ^ (c >> 1) ^ (c >> 2) ^ (c >> 4) ^ (c >> 6) ^ (c >> 12);
                buf[i] = buf[i] ^ (u_char)(c) ^ key[(file_pos+i)%key_len];
            }
            cl->buf->in_file = 0;
        }
        else
        {
            return NGX_HTTP_FORBIDDEN;
        }
        cl = cl->next;
    }

    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t
ngx_file_encrypt_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_encrypt_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_encrypt_body_filter;
    return NGX_OK;
}

static void *
ngx_file_encrypt_create_conf(ngx_conf_t *cf)
{
    ngx_file_encrypt_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_file_encrypt_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }
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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_stream.h>

static ngx_int_t ngx_stream_auto_proxy_protocol_init(ngx_conf_t *cf);
static void *ngx_stream_auto_proxy_protocol_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_auto_proxy_protocol_merge_srv_conf(ngx_conf_t *cf, 
    void *parent, void *child);

typedef struct {
    ngx_flag_t enable;
    ngx_msec_t timeout;
} ngx_stream_auto_proxy_protocol_srv_conf_t;

static ngx_command_t ngx_stream_auto_proxy_protocol_commands[] = {
    {
        ngx_string("auto_proxy_protocol"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_stream_auto_proxy_protocol_srv_conf_t, enable),
        NULL
    },
    {
        ngx_string("auto_proxy_protocol_timeout"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_msec_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_stream_auto_proxy_protocol_srv_conf_t, timeout),
        NULL
    },
    ngx_null_command
};

static ngx_stream_module_t ngx_stream_auto_proxy_protocol_module_ctx = {
    NULL,                                            /* preconfiguration */
    ngx_stream_auto_proxy_protocol_init,             /* postconfiguration */
    NULL,                                            /* create main configuration */
    NULL,                                            /* init main configuration */
    ngx_stream_auto_proxy_protocol_create_srv_conf,  /* create server configuration */
    ngx_stream_auto_proxy_protocol_merge_srv_conf,   /* merge server configuration */
};

ngx_module_t ngx_stream_auto_proxy_protocol_module = {
    NGX_MODULE_V1,
    &ngx_stream_auto_proxy_protocol_module_ctx, /* module context */
    ngx_stream_auto_proxy_protocol_commands,    /* module directives */
    NGX_STREAM_MODULE,                          /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};



static void *ngx_stream_auto_proxy_protocol_create_srv_conf(ngx_conf_t *cf) 
{
    ngx_stream_auto_proxy_protocol_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_auto_proxy_protocol_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *ngx_stream_auto_proxy_protocol_merge_srv_conf(ngx_conf_t *cf, 
    void *parent, void *child)
{
    ngx_stream_auto_proxy_protocol_srv_conf_t *prev = parent;
    ngx_stream_auto_proxy_protocol_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 1000);

    return NGX_CONF_OK;
}



static ngx_int_t
ngx_stream_auto_proxy_protocol_handler(ngx_stream_session_t *s)
{
    ngx_stream_auto_proxy_protocol_srv_conf_t  *appcf;
    ngx_connection_t                           *c;
    size_t                                      size;
    ssize_t                                     n;
    u_char                                     *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER];
    ngx_err_t                                   err;
    ngx_event_t                                *rev;

    appcf = ngx_stream_get_module_srv_conf(s, ngx_stream_auto_proxy_protocol_module);
    if (!appcf->enable) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "auto_proxy_protocol: not enabled");
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "auto_proxy_protocol: enabled");

    c = s->connection;
    if (c->proxy_protocol) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "auto_proxy_protocol: proxy_protocol already parsed");
        return NGX_DECLINED;
    }

    if (c->read->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "auto_proxy_protocol: timeout, skip parsing proxy_protocol");
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "auto_proxy_protocol: parsing proxy_protocol");

    n = recv(c->fd, buf, sizeof(buf), MSG_PEEK);
    err = ngx_socket_errno;
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "recv(): %z", n);

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "auto_proxy_protocol: EAGAIN");
            rev = c->read;
            if (!rev->timer_set) {
                ngx_add_timer(rev, appcf->timeout);
            }
            return NGX_AGAIN;
        }

        ngx_connection_error(c, err, "recv() failed");
        return NGX_ERROR;
    }

    p = ngx_proxy_protocol_read(c, buf, buf + n);
    if (p) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "auto_proxy_protocol: proxy_protocol successfully parsed");
        size = p - buf;
        if (recv(c->fd, buf, size, 0) != (ssize_t) size) {
            return NGX_ERROR;
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t ngx_stream_auto_proxy_protocol_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt *h;
    ngx_stream_core_main_conf_t *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_STREAM_POST_ACCEPT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_stream_auto_proxy_protocol_handler;
    return NGX_OK;
}
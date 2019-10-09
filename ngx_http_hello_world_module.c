#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdbool.h>
 
typedef struct {
    ngx_str_t output_words;
} ngx_http_hello_world_loc_conf_t;
 
static char* ngx_http_hello_world(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
 
static void* ngx_http_hello_world_create_loc_conf(ngx_conf_t* cf);
 
static char* ngx_http_hello_world_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);
 

// reference for ngx_command_t
// struct ngx_command_s {
//     ngx_str_t             name;
//     ngx_uint_t            type;
//     char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//     ngx_uint_t            conf;
//     ngx_uint_t            offset;
//     void                 *post;
// };w

static ngx_command_t ngx_http_hello_world_commands[] = {
    {
        ngx_string("hello_world"), 
        // NGX_HTTP_LOC_CONF：可出现在 http 的 location 作用域
        // NGX_CONF_TAKE1：指令读入1个参数；
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        // 命令回调函数
        ngx_http_hello_world, 
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hello_world_loc_conf_t, output_words),
        NULL
    },
    ngx_null_command
};


// 上下文定义
static ngx_http_module_t ngx_http_hello_world_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    // location 创建函数    
    ngx_http_hello_world_create_loc_conf,
    // location 合并函数
    ngx_http_hello_world_merge_loc_conf
};
 
// reference for ngx_module_t
// struct ngx_module_s {
//     ngx_uint_t            ctx_index; 
//     ngx_uint_t            index; 
 
//     ngx_uint_t            spare0;
//     ngx_uint_t            spare1;
//     ngx_uint_t            spare2;
//     ngx_uint_t            spare3;
 
//     ngx_uint_t            version; // Nginx模块版本
 
//     void                 *ctx; // 上下文定义的地址
//     ngx_command_t        *commands; // 命令定义地址
//     ngx_uint_t            type; // 模块类型
 
//     ngx_int_t           (*init_master)(ngx_log_t *log); // 初始化 master 时执行
 
//     ngx_int_t           (*init_module)(ngx_cycle_t *cycle); // 初始化模块时执行
 
//     ngx_int_t           (*init_process)(ngx_cycle_t *cycle); // 初始化进程时执行
//     ngx_int_t           (*init_thread)(ngx_cycle_t *cycle); // 初始化线程时执行
//     void                (*exit_thread)(ngx_cycle_t *cycle); // 退出线程时执行
//     void                (*exit_process)(ngx_cycle_t *cycle); // 退出进程时执行
 
//     void                (*exit_master)(ngx_cycle_t *cycle); // 退出 master 时执行
 
//     uintptr_t             spare_hook0;
//     uintptr_t             spare_hook1;
//     uintptr_t             spare_hook2;
//     uintptr_t             spare_hook3;
//     uintptr_t             spare_hook4;
//     uintptr_t             spare_hook5;
//     uintptr_t             spare_hook6;
//     uintptr_t             spare_hook7;
// };

// Structure for the HelloWorld module, the most important thing
ngx_module_t ngx_http_hello_world_module = {
    // NGX_MODULE_V1          0, 0, 0, 0, 0, 0, 1 padding the ngx_module_s
    NGX_MODULE_V1,
    &ngx_http_hello_world_module_ctx,
    ngx_http_hello_world_commands,
    // #define NGX_HTTP_MODULE      0x50545448   /* "HTTP" */
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


void strcat_ngx_array(ngx_array_t* a, u_char* res)
{
    bool flag = true;
    

    if (a)
    {
        ngx_uint_t          i, n;
        ngx_table_elt_t     **h;

        n = a->nelts;
        h = a->elts;

        for (i = 0; i < n; i++) {
            if(h[i]->value.data != NULL)
            {
                flag = false;
                strncat(res, h[i]->value.data, h[i]->value.len);
            }
        }
        if(flag)
        {
            strcat(res, "NO PASS ON\0"); 
        }
    }
    else
    {
        strcat(res, "NO PASS ON\0"); 
    }
}


// TODO: get the body
void strcat_ngx_chain(ngx_chain_t* a, u_char* res)
{

    bool flag = true;

    // strcat(res, "NO PASS ON\0");  
    if (a)
    {
        ngx_chain_t     *cl;
        cl = a;
        size_t i = 1;
        if(i--)
        // for(; cl; cl=cl->next) 
        {
            flag = false;
            res = strcat(res, "NO PASS ON111\0");
            // strcat(res, (u_char*)cl->buf->startemporaryt);
            // strcat(res, *(bufs->next->buf->start));

        }
        if(flag)
        {
            strcat(res, "NO PASS ON\0");  
        }
    }
    else
    {
        strcat(res, "NO PASS ON\0");
    }
}


static ngx_int_t ngx_http_hello_world_handler(ngx_http_request_t* r) {
    ngx_int_t rc;
    ngx_buf_t* b;
    ngx_chain_t out[10];
 
    u_char first_part[4096] = {0};
    ngx_uint_t content_length = 0;
    // ngx_http_hello_world_loc_conf_t* hlcf;
    // hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hello_world_module);
 
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char*)"text/plain";
    u_char* connection_key;
    u_char* connection_value;
    u_char* if_modified_since_key;
    u_char* if_modified_since_value;
    u_char* if_unmodified_since_key;
    u_char* if_unmodified_since_value;
    u_char* if_match_key;
    u_char* if_match_value;
    u_char* if_none_match_key;
    u_char* if_none_match_value;
    u_char* user_agent_key;
    u_char* user_agent_value;
    u_char* referer_key;
    u_char* referer_value;
    u_char* content_length_key;
    u_char* content_length_value;
    u_char* content_range_key;
    u_char* content_range_value;
    u_char* content_type_key;
    u_char* content_type_value;

    u_char* range_key;
    u_char* range_value;
    u_char* if_range_key;
    u_char* if_range_value;
    u_char* transfer_encoding_key;
    u_char* transfer_encoding_value;

    u_char* te_key;
    u_char* te_value;
    u_char* expect_key;
    u_char* expect_value;
    u_char* upgrade_key;
    u_char* upgrade_value;

    u_char* accept_encoding_key;
    u_char* accept_encoding_value;
    u_char* via_key;
    u_char* via_value;
    u_char* authorization_key;
    u_char* authorization_value;

    u_char* keep_alive_key;
    u_char* keep_alive_value;
    
    u_char* x_real_ip_key;
    u_char* x_real_ip_value;

    u_char* accept_key;
    u_char* accept_value;
    u_char* accept_language_key;
    u_char* accept_language_value;
    u_char* depth_key;
    u_char* depth_value;

    u_char* destination_key;
    u_char* destination_value;
    u_char* overwrite_key;
    u_char* overwrite_value;
    u_char* date_key;
    u_char* date_value;

    u_char* user_key;
    u_char* user_value;
    u_char* passwd_key;
    u_char* passwd_value;
    u_char* server_key;
    u_char* server_value;
    u_char* body_key;

    u_char* x_forwarded_for_key = (u_char*)"x_forwarded_for";

    u_char* cookies_key = (u_char*)"cookie";

    ngx_array_t cookies = r->headers_in.cookies;
    u_char* cookies_value = (u_char*)malloc(sizeof(u_char)*1024);
    memset(cookies_value, 0, 1024);
    strcat_ngx_array(&cookies, cookies_value);

    #if (NGX_HTTP_X_FORWARDED_FOR)

        ngx_array_t x_forwarded_for = r->headers_in.x_forwarded_for;
        u_char* x_forwarded_for_value = (u_char*)malloc(sizeof(u_char)*1024);
        memset(x_forwarded_for_value, 0, 1024);
        strcat_ngx_array(&x_forwarded_for, x_forwarded_for_value);

    #else
        u_char* x_forwarded_for_value = (u_char*)"NO DEFINE";
    #endif

    body_key = (u_char*)"body";
    u_char* body_value = (u_char*)malloc(sizeof(u_char)*1024);
    memset(body_value, 0, 1024);

    strcat_ngx_chain(&r->request_body->bufs, body_value);

    // 两个三目应该会比一个if好
    connection_key = r->headers_in.connection ? r->headers_in.connection->key.data : (u_char*)"connection";
    connection_value = r->headers_in.connection ? r->headers_in.connection->value.data : (u_char*)"NO PASS ON";
    if_modified_since_key = r->headers_in.if_modified_since ? r->headers_in.if_modified_since->key.data : (u_char*)"if_modified_since";
    if_modified_since_value = r->headers_in.if_modified_since ? r->headers_in.if_modified_since->value.data : (u_char*)"NO PASS ON";
    if_unmodified_since_key = r->headers_in.if_unmodified_since ? r->headers_in.if_unmodified_since->key.data : (u_char*)"if_unmodified_since";
    if_unmodified_since_value = r->headers_in.if_unmodified_since ? r->headers_in.if_unmodified_since->value.data : (u_char*)"NO PASS ON";    
    if_match_key = r->headers_in.if_match ? r->headers_in.if_match->key.data : (u_char*)"if_match";
    if_match_value = r->headers_in.if_match ? r->headers_in.if_match->value.data : (u_char*)"NO PASS ON";

    if_none_match_key = r->headers_in.if_none_match ? r->headers_in.if_none_match->key.data : (u_char*)"if_none_match";
    if_none_match_value = r->headers_in.if_none_match ? r->headers_in.if_none_match->value.data : (u_char*)"NO PASS ON";
    user_agent_key = r->headers_in.user_agent ? r->headers_in.user_agent->key.data : (u_char*)"user_agent";
    user_agent_value = r->headers_in.user_agent ? r->headers_in.user_agent->value.data : (u_char*)"NO PASS ON";
    referer_key = r->headers_in.referer ? r->headers_in.referer->key.data : (u_char*)"referer";
    referer_value = r->headers_in.referer ? r->headers_in.referer->value.data : (u_char*)"NO PASS ON";

    content_length_key = r->headers_in.content_length ? r->headers_in.content_length->key.data : (u_char*)"content_length";
    content_length_value = r->headers_in.content_length ? r->headers_in.content_length->value.data : (u_char*)"NO PASS ON";
    content_range_key = r->headers_in.content_range ? r->headers_in.content_range->key.data : (u_char*)"content_range";
    content_range_value = r->headers_in.content_range ? r->headers_in.content_range->value.data : (u_char*)"NO PASS ON";
    content_type_key = r->headers_in.content_type ? r->headers_in.content_type->key.data : (u_char*)"content_type";
    content_type_value = r->headers_in.content_type ? r->headers_in.content_type->value.data : (u_char*)"NO PASS ON";

    range_key = r->headers_in.range ? r->headers_in.range->key.data : (u_char*)"range";
    range_value = r->headers_in.range ? r->headers_in.range->value.data : (u_char*)"NO PASS ON";
    if_range_key = r->headers_in.if_range ? r->headers_in.if_range->key.data : (u_char*)"if_range";
    if_range_value = r->headers_in.if_range ? r->headers_in.if_range->value.data : (u_char*)"NO PASS ON";
    transfer_encoding_key = r->headers_in.transfer_encoding ? r->headers_in.transfer_encoding->key.data : (u_char*)"transfer_encoding";
    transfer_encoding_value = r->headers_in.transfer_encoding ? r->headers_in.transfer_encoding->value.data : (u_char*)"NO PASS ON";

    te_key = r->headers_in.te ? r->headers_in.te->key.data : (u_char*)"te";
    te_value = r->headers_in.te ? r->headers_in.te->value.data : (u_char*)"NO PASS ON";
    expect_key = r->headers_in.expect ? r->headers_in.expect->key.data : (u_char*)"expect";
    expect_value = r->headers_in.expect ? r->headers_in.expect->value.data : (u_char*)"NO PASS ON";
    upgrade_key = r->headers_in.upgrade ? r->headers_in.upgrade->key.data : (u_char*)"upgrade";
    upgrade_value = r->headers_in.upgrade ? r->headers_in.upgrade->value.data : (u_char*)"NO PASS ON";

    #if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
        accept_encoding_key = r->headers_in.accept_encoding ? r->headers_in.accept_encoding->key.data : (u_char*)"accept_encoding";
        accept_encoding_value = r->headers_in.accept_encoding ? r->headers_in.accept_encoding->value.data : (u_char*)"NO DEFINE";
        via_key = r->headers_in.via ? r->headers_in.via->key.data : (u_char*)"via";
        via_value = r->headers_in.via ? r->headers_in.via->value.data : (u_char*)"NO DEFINE";
    #else
        accept_encoding_key = (u_char*)"accept_encoding";
        accept_encoding_value = (u_char*)"NO DEFINE";
        via_key = (u_char*)"via";
        via_value = (u_char*)"NO DEFINE";
    #endif
    
    authorization_key = r->headers_in.authorization ? r->headers_in.authorization->key.data : (u_char*)"authorization";
    authorization_value = r->headers_in.authorization ? r->headers_in.authorization->value.data : (u_char*)"NO PASS ON";

    keep_alive_key = r->headers_in.keep_alive ? r->headers_in.keep_alive->key.data : (u_char*)"te";
    keep_alive_value = r->headers_in.keep_alive ? r->headers_in.keep_alive->value.data : (u_char*)"NO PASS ON";
    

    
    #if (NGX_HTTP_REALIP)
        x_real_ip_key = r->headers_in.x_real_ip ? r->headers_in.x_real_ip->key.data : (u_char*)"x_real_ip";
        x_real_ip_value = r->headers_in.x_real_ip ? r->headers_in.x_real_ip->value.data : (u_char*)"NO PASS ON";
    #else
        x_real_ip_key = (u_char*)"x_real_ip";
        x_real_ip_value = (u_char*)"NO DEFINE";
    #endif
    
    #if (NGX_HTTP_HEADERS)
        accept_key = r->headers_in.accept ? r->headers_in.accept->key.data : (u_char*)"accept";
        accept_value = r->headers_in.accept ? r->headers_in.accept->value.data : (u_char*)"NO PASS ON";
        accept_language_key = r->headers_in.accept_language ? r->headers_in.accept_language->key.data : (u_char*)"accept_language";
        accept_language_value = r->headers_in.accept_language ? r->headers_in.accept_language->value.data : (u_char*)"NO PASS ON";
    #else
        accept_key = (u_char*)"accept";
        accept_value = (u_char*)"NO DEFINE";
        accept_language_key = (u_char*)"accept_language";
        accept_language_value = (u_char*)"NO DEFINE";
    #endif
    
    #if (NGX_HTTP_DAV)
        depth_key = r->headers_in.depth ? r->headers_in.depth->key.data : (u_char*)"depth";
        depth_value = r->headers_in.depth ? r->headers_in.depth->value.data : (u_char*)"NO PASS ON";

        destination_key = r->headers_in.destination ? r->headers_in.destination->key.data : (u_char*)"destination";
        destination_value = r->headers_in.destination ? r->headers_in.destination->value.data : (u_char*)"NO PASS ON";
        overwrite_key = r->headers_in.overwrite ? r->headers_in.overwrite->key.data : (u_char*)"overwrite";
        overwrite_value = r->headers_in.overwrite ? r->headers_in.overwrite->value.data : (u_char*)"NO PASS ON";
        date_key = r->headers_in.date ? r->headers_in.date->key.data : (u_char*)"date";
        date_value = r->headers_in.date ? r->headers_in.date->value.data : (u_char*)"NO PASS ON";

    #else
        depth_key = (u_char*)"depth";
        depth_value = (u_char*)"NO DEFINE";
        destination_key = (u_char*)"destination";
        destination_value = (u_char*)"NO DEFINE";
        overwrite_key = (u_char*)"overwrite";
        overwrite_value = (u_char*)"NO DEFINE";
        date_key = (u_char*)"date";
        date_value = (u_char*)"NO DEFINE";
    #endif

    user_key = (u_char*)"user";
    user_value = r->headers_in.user.len ? r->headers_in.user.data : (u_char*)"NO PASS ON";
    passwd_key = (u_char*)"passwd";
    passwd_value = r->headers_in.passwd.len ? r->headers_in.passwd.data : (u_char*)"NO PASS ON";   
    server_key = (u_char*)"server";
    server_value = r->headers_in.server.len ? r->headers_in.server.data : (u_char*)"NO PARSE TO";
    // user_value = r->headers_in.server.data;

    ngx_sprintf(first_part, "NO PASSON ON代表没传递,这些值的顺序是按照nginx源码中ngx_http_request.h的ngx_http_headers_in_t结构体中按照顺序写的,并且没传递的key都是小写（方便）\nrequest_line: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n", r->request_line.data, r->headers_in.host->key.data, r->headers_in.host->value.data, connection_key, connection_value, if_modified_since_key, if_modified_since_value, if_unmodified_since_key, if_unmodified_since_value, if_match_key, if_match_value, if_none_match_key, if_none_match_value, user_agent_key, user_agent_value, referer_key, referer_value, content_length_key, content_length_value, content_range_key, content_range_value, content_type_key, content_type_value, range_key, range_value, if_range_key, if_range_value, transfer_encoding_key, transfer_encoding_value, te_key, te_value, expect_key, expect_value, upgrade_key, upgrade_value, accept_encoding_key, accept_encoding_value, via_key, via_value, authorization_key, authorization_value, keep_alive_key, keep_alive_value, x_forwarded_for_key, x_forwarded_for_value, x_real_ip_key, x_real_ip_value, accept_key, accept_value, accept_language_key, accept_language_value, depth_key, depth_value, destination_key, destination_value, overwrite_key, overwrite_value, date_key, date_value, user_key, user_value, passwd_key, passwd_value, server_key, server_value, cookies_key, cookies_value, body_key, body_value);
    content_length = ngx_strlen(first_part);
 
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* attach this buffer to the buffer chain */
    out[0].buf = b;
    out[0].next = NULL;
 
     /* adjust the pointers of the buffer */
    b->pos = first_part;
    b->last = first_part + content_length;
    b->memory = 1;    /* this buffer is in memory */
    b->last_buf = 1;  /* this is the last buffer in the buffer chain */
    // b->pos = hlcf->output_words.data;
    // b->last = hlcf->output_words.data + (hlcf->output_words.len);
    // b->memory = 1;
    // b->last_buf = 1;
 
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = content_length;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
 
    return ngx_http_output_filter(r, &out[0]);
}
/**
  *分配一段 ngx_http_hello_world_loc_conf_t 所使用的大小的内存。
  *并初始化 ngx_http_hello_world_loc_conf_t 唯一的成员 output_words
  */
static void* ngx_http_hello_world_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_hello_world_loc_conf_t* conf;
 
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_world_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->output_words.len = 0;
    conf->output_words.data = NULL;
 
    return conf;
}
 
static char* ngx_http_hello_world_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child) {
    ngx_http_hello_world_loc_conf_t* prev = parent;
    ngx_http_hello_world_loc_conf_t* conf = child;
    ngx_conf_merge_str_value(conf->output_words, prev->output_words, "Nginx");
    return NGX_CONF_OK;
}
/** 这个函数的作用，就是生成对请求的响应内容，即本例中的hello_world, Poechant。
  * 然后获取到 http_core_module 的 location configuration
  * 即 clcf（Core Location ConF）。给 clcf 的 handler 字段赋值 
  * ngx_http_hello_world_handler
  */ 

static char* ngx_http_hello_world(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_core_loc_conf_t* clcf;
    // 它的作用是通过 cf 配置的上下文，找到指定的 module 中的 location configuration。
    // ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hello_world_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

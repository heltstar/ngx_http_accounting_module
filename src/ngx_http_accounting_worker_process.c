#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <syslog.h>
#include <string.h>

#include "ngx_http_accounting_hash.h"
#include "ngx_http_accounting_module.h"
#include "ngx_http_accounting_common.h"
#include "ngx_http_accounting_status_code.h"
#include "ngx_http_accounting_worker_process.h"

#include "ngx_http_accounting_hash_json.h"

#define WORKER_PROCESS_TIMER_INTERVAL   30       /* In seconds */

static ngx_event_t  write_out_ev;
static ngx_http_accounting_hash_t  stats_hash;

static ngx_int_t ngx_http_accounting_old_time = 0;
static ngx_int_t ngx_http_accounting_new_time = 0;

static u_char *ngx_http_accounting_title = (u_char *)"NgxAccounting";

static void worker_process_alarm_handler(ngx_event_t *ev);
static ngx_str_t *get_accounting_id(ngx_http_request_t *r);

static int array_num = 10;
static char *out= NULL;
static hash_json_t *hjt_root = NULL;
static cJSON *cjson_root = NULL;
static u_char origin_host[256] = "\0";
static int origin_port = 0;

ngx_int_t
ngx_http_accounting_worker_process_init(ngx_cycle_t *cycle)
{
    ngx_int_t rc;
    ngx_time_t  *time;
    ngx_http_accounting_main_conf_t *amcf;

    openlog((char *)ngx_http_accounting_title, LOG_NDELAY, LOG_SYSLOG);
    amcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_accounting_module);

    if (!amcf->enable) {
        return NGX_OK;
    }
    //origin_host = amcf->origin_host.data;
    ngx_snprintf(origin_host, amcf->origin_host.len, "%s", amcf->origin_host.data);
    u_char tmp[8] = "\0";
    ngx_snprintf(tmp, amcf->origin_port.len, "%s", amcf->origin_port.data);
    origin_port = atoi((char*)tmp);

    syslog(LOG_INFO, "origin_host-------------origin_port");
    syslog(LOG_INFO, "host:%s, port:%d",origin_host, origin_port);
    init_http_status_code_map();

    time = ngx_timeofday();

    ngx_http_accounting_old_time = time->sec;
    ngx_http_accounting_new_time = time->sec;

    //openlog((char *)ngx_http_accounting_title, LOG_NDELAY, LOG_SYSLOG);
    syslog(LOG_INFO, "pid:%i|Process:init", ngx_getpid());

    rc = ngx_http_accounting_hash_init(&stats_hash, NGX_HTTP_ACCOUNTING_NR_BUCKETS, cycle->pool);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&write_out_ev, sizeof(ngx_event_t));

    write_out_ev.data = NULL;
    write_out_ev.log = cycle->log;
    write_out_ev.handler = worker_process_alarm_handler;

    srand(ngx_getpid());
    //ngx_add_timer(&write_out_ev, WORKER_PROCESS_TIMER_INTERVAL*(1000-rand()%200));
    ngx_add_timer(&write_out_ev, WORKER_PROCESS_TIMER_INTERVAL*4);

    syslog(LOG_INFO, "hash_json_init");
    hjt_root = hash_json_init(array_num);

    return NGX_OK;
}


void ngx_http_accounting_worker_process_exit(ngx_cycle_t *cycle)
{
    ngx_http_accounting_main_conf_t *amcf;

    amcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_accounting_module);

    if (!amcf->enable) {
        return;
    }

    worker_process_alarm_handler(NULL);

    syslog(LOG_INFO, "hash_json_destroy() start");
    hash_json_destroy(hjt_root);
    syslog(LOG_INFO, "hash_json_destroy() end");
    syslog(LOG_INFO, "pid:%i|Process:exit", ngx_getpid());
}


    ngx_int_t
ngx_http_accounting_handler(ngx_http_request_t *r)
{
    ngx_str_t      *accounting_id;
    ngx_uint_t      key;

    ngx_uint_t      status;
    ngx_uint_t     *status_array;

    ngx_http_accounting_stats_t *stats;

    long user_id = 0, business_id = 0 ,traffic = 0;

    accounting_id = get_accounting_id(r);

    syslog(LOG_INFO, "ngx_http_accounting_handler() start");
    // TODO: key should be cached to save CPU time
    key = ngx_hash_key_lc(accounting_id->data, accounting_id->len);
    stats = ngx_http_accounting_hash_find(&stats_hash, key, accounting_id->data, accounting_id->len);

    if (stats == NULL) {

        syslog(LOG_INFO, "ngx_http_accounting_handler() stats== NULL");
        stats = ngx_pcalloc(stats_hash.pool, sizeof(ngx_http_accounting_stats_t));
        status_array = ngx_pcalloc(stats_hash.pool, sizeof(ngx_uint_t) * http_status_code_count);

        if (stats == NULL || status_array == NULL)
            return NGX_ERROR;

        stats->http_status_code = status_array;
        ngx_http_accounting_hash_add(&stats_hash, key, accounting_id->data, accounting_id->len, stats);
    }

    if (r->err_status) {
        status = r->err_status;
    } else if (r->headers_out.status) {
        status = r->headers_out.status;
    } else {
        status = NGX_HTTP_DEFAULT;
    }

    stats->nr_requests += 1;
    stats->bytes_in += r->request_length;

    stats->bytes_out += r->connection->sent;
    stats->http_status_code[http_status_code_to_index_map[status]] += 1;

    if((r->method == NGX_HTTP_GET) && (r->headers_out.status == NGX_HTTP_OK || r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT)) { // add for user-bisiness-traffic
        u_char req_str_t[256];
        syslog(LOG_INFO, "user-business-traffic process");
        ngx_snprintf(req_str_t, r->uri.len, "%s", r->uri.data);
        char *index = strstr((char*)req_str_t, "/cdn/");
        if(NULL != index) {
            char *p = strtok((char*)req_str_t + sizeof("/cdn/"), "/");
            int n = 0;
            while(p) {
                if(n == 1) {
                    user_id = atoi(p);
                } else if (n ==2) {
                    business_id = atoi(p);
                    break;
                }
                p = strtok(NULL, "/");
                n++;
            }
            traffic = r->connection->sent;
            syslog(LOG_INFO, "insert inti hash_json itme: user_id:%ld, business_id:%ld, traffic:%ld",user_id, business_id, traffic);
            hash_json_insert_into_item(hjt_root, user_id, business_id, traffic);
        }
        else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, " request path has no '/cdn/' ");
        }
    }

    return NGX_OK;
}


    static ngx_int_t
worker_process_write_out_stats(u_char *name, size_t len, void *val, void *para1, void *para2)
{
    ngx_uint_t   i;
    ngx_http_accounting_stats_t  *stats;

    char temp_buffer[128];
    char output_buffer[1024];

    stats = (ngx_http_accounting_stats_t *)val;

    if (stats->nr_requests == 0) {
        return NGX_OK;
    }

    sprintf(output_buffer, "pid:%i|from:%ld|to:%ld|accounting_id:%s|requests:%ld|bytes_in:%ld|bytes_out:%ld",
            ngx_getpid(),
            ngx_http_accounting_old_time,
            ngx_http_accounting_new_time,
            name,
            stats->nr_requests,
            stats->bytes_in,
            stats->bytes_out
           );

    stats->nr_requests = 0;
    stats->bytes_out = 0;
    stats->bytes_in = 0;

    for (i = 0; i < http_status_code_count; i++) {
        if(stats->http_status_code[i] > 0) {
            sprintf(temp_buffer, "|%ld:%ld",
                    index_to_http_status_code_map[i],
                    stats->http_status_code[i]);

            strcat(output_buffer, temp_buffer);

            stats->http_status_code[i] = 0;
        }
    }

    syslog(LOG_INFO, "%s", output_buffer);

    syslog(LOG_INFO, "hash_json_create_object() start");
    cjson_root = hash_json_create_object(hjt_root);// user-business-traffic
    if(NULL == cjson_root) {
        //printf("NULL == cjson_root \n");
        return -1; 
    }   
    out=cJSON_Print(cjson_root);
    syslog(LOG_INFO, "hash_json_create_object() end");
    int rt = 0;
    if(strlen((char*)origin_host) > 0 && origin_port > 0) {
        syslog(LOG_INFO, "strlen((char*)origin_host) > 0");
        //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, " send_to_origin() start ");
        rt = send_to_origin((char*)origin_host, origin_port, out, strlen(out));
        if(rt < 0) {
            //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, " send_to_origin() failed");
            syslog(LOG_INFO, "send_to_origin() ret < 0");
        }
    }

    syslog(LOG_INFO, "send_to_origin() over free mem.");
    free(out);
    cJSON_Delete(cjson_root);
    hash_json_destroy(hjt_root);
    cjson_root = NULL;
    hjt_root = NULL;
    out = NULL;

    hjt_root = hash_json_init(array_num);
    if(NULL != hjt_root) {
        syslog(LOG_INFO, "hash_json_init() init again.");
    }

    return NGX_OK;
}


    static void
worker_process_alarm_handler(ngx_event_t *ev)
{
    ngx_time_t  *time;
    ngx_msec_t   next;

    time = ngx_timeofday();

    ngx_http_accounting_old_time = ngx_http_accounting_new_time;
    ngx_http_accounting_new_time = time->sec;

    ngx_http_accounting_hash_iterate(&stats_hash, worker_process_write_out_stats, NULL, NULL);

    if (ngx_exiting || ev == NULL)
        return;

    next = (ngx_msec_t)WORKER_PROCESS_TIMER_INTERVAL * 1000;

    ngx_add_timer(ev, next);
}


    static ngx_str_t *
get_accounting_id(ngx_http_request_t *r)
{
    ngx_http_accounting_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_accounting_module);

    return &alcf->accounting_id;
}

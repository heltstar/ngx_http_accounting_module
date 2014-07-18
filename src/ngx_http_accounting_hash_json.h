#ifndef __HASH_JSON_H__
#define __HASH_JSON_H__

#include "ngx_http_accounting_cJSON.h"
    

typedef struct record_s record_t;
struct record_s {
    long user_id;
    long traffic;
    record_t *next;
};

typedef struct user_key_array_s  user_key_array_t;
struct user_key_array_s {
    record_t *record_head;
};

typedef struct business_id_list_s  business_id_list_t;
struct business_id_list_s {
    long business_id;
    user_key_array_t *user_key_array;
    business_id_list_t *next;
};

typedef struct hash_json_s  hash_json_t;
struct hash_json_s {
    long bil_num;
    long user_key_array_num;
    business_id_list_t *bil_head;
};

hash_json_t *hash_json_init(long user_key_array_num);
int hash_json_insert_into_item(hash_json_t *hjt, long user_id, long business_id, long traffic);
int hash_json_destroy(hash_json_t *hjt);
cJSON *hash_json_create_object(hash_json_t *hjt);

int send_to_origin(char *host, int port, char *out, long out_size);

#endif

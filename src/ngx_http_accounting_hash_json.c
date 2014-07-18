#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "ngx_http_accounting_hash_json.h"


//int PORT = 8080;
//char *HOST= "192.168.56.102";

hash_json_t *
hash_json_init(long user_key_array_num)
{
    hash_json_t * root;
    
    if(0 >= user_key_array_num){
        return NULL;
    }

    root = (hash_json_t*)malloc(sizeof(hash_json_t));
    if(NULL == root){
        return NULL;
    }
    root->bil_num = 0;
    root->user_key_array_num = user_key_array_num;
    root->bil_head = NULL;

    return root;
}

int
hash_json_insert_into_item(hash_json_t *hjt, long user_id, long business_id, long traffic)
{
    business_id_list_t *bil;
    record_t *rcd;
    user_key_array_t *uka;
    long user_key;

    bil = hjt->bil_head;
    while(NULL != bil) {
        if(business_id == bil->business_id) {
            break;
        }
        bil = bil->next;
    }
    if(NULL == bil) {
        bil = (business_id_list_t *)malloc(sizeof(business_id_list_t));
        if(NULL == bil){
            hash_json_destroy(hjt);
            return -1;
        }
        bil->business_id = business_id;
        hjt->bil_num++;

        uka = (user_key_array_t *)malloc(sizeof(user_key_array_t)* hjt->user_key_array_num);
        if(NULL == uka){
            hash_json_destroy(hjt);
            return -1;
        }
        memset(uka, 0, sizeof(user_key_array_t)* hjt->user_key_array_num);
        bil->user_key_array = uka;
        bil->next = hjt->bil_head;
        hjt->bil_head = bil;
//        printf("bil not find: hjt->bil_num = %ld\n", hjt->bil_num);
    }

    uka= bil->user_key_array;
    user_key =  user_id % hjt->user_key_array_num;
    rcd = uka[user_key].record_head;
    while(NULL != rcd) {
        if(user_id == rcd->user_id) {
            rcd->traffic += traffic;
//            printf("find: rcd->user_id = %ld, traffic = %ld\n", user_id, rcd->traffic);
            return 0;
        }
        rcd = rcd->next; 
    }

    if(NULL == rcd){
        rcd = (record_t*)malloc(sizeof(record_t));
        if(NULL == rcd) {
            return -1;
        }
        rcd->user_id = user_id;
        rcd->traffic = traffic;
//        printf("not find: rcd->user_id = %ld, traffic = %ld\n", user_id, traffic);

        rcd->next = uka[user_key].record_head;
        uka[user_key].record_head = rcd;
    }

    return 0;
}


    cJSON*
hash_json_create_object(hash_json_t *hjt)
{
    cJSON *root,*arr, *fld;
    business_id_list_t *bil;
    record_t *rcd;
    user_key_array_t *uka;
    char str_key[128] = "";
    int i;

    if(hjt == NULL){
        return NULL;
    }

    bil = hjt->bil_head;
    root=cJSON_CreateObject();	

    while(NULL != bil){
        sprintf(str_key,"%lu", bil->business_id);
        cJSON_AddItemToObject(root, str_key, arr = cJSON_CreateArray());
        uka = bil->user_key_array;

        for(i = 0; i< hjt->user_key_array_num; i++) {
            rcd = uka[i].record_head; 
            while(NULL != rcd) {
                cJSON_AddItemToArray(arr ,fld=cJSON_CreateObject());
                cJSON_AddNumberToObject(fld, "user_id", rcd->user_id);
                cJSON_AddNumberToObject(fld, "traffic", rcd->traffic);

                rcd = rcd->next;
            }
        }
        bil = bil->next;
    }

    return root; 
}



    int 
hash_json_destroy(hash_json_t *hjt)
{
    business_id_list_t *bil, *bil_tmp;
    record_t *rcd, *rcd_tmp;
    user_key_array_t *uka;
    int i;

    if(hjt == NULL){
        return 0;
    }
    bil = hjt->bil_head;
    while(NULL != bil){
        bil_tmp = bil->next;

        uka = bil->user_key_array;
        for(i = 0; i< hjt->user_key_array_num; i++) {
            rcd = uka[i].record_head; 
            while(NULL != rcd) {
                rcd_tmp = rcd->next; 
                free(rcd);
                rcd = rcd_tmp;
            }
        }
        free(uka);
        free(bil);
        bil = bil_tmp;
    }
    free(hjt);

    return 0;
}

    int 
send_to_origin(char *host, int port, char *out, long out_size) 
{
    int sockfd = -1;

    if(NULL == out) {
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
//        printf("%s", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    memset(&addr, '\0', addrlen);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    int ret = connect(sockfd, (struct sockaddr *)&addr, addrlen);
    if (ret == -1) {
//        printf("%s", strerror(errno));
        return -1;
    }
//    printf("\nconnect %s at PORT %d success, will send: %ld bytes\n", HOST, PORT, out_size);

    long s = 0;
    long offset = 0;

    while (out_size > 0) {
        s = write(sockfd, out, out_size);
        if (s == -1) {
//            printf("%s", strerror(errno));
            return -1;
        }
        out += s;
        offset += s;
//        printf("offset=%ld\n", offset);
        out_size -= s;
    }
    sleep(2);
///    printf("send %s at PORT %d success: %ld bytes \n", HOST, PORT, offset);
    ret = close(sockfd);
    if (ret == -1) {
//        printf("%s", strerror(errno));
        return -1;
    }

    return 0;
}

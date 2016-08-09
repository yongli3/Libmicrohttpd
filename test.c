#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define NETIFNAME   "enp2s0"
#define SERVERURL   "http://localhost:8080/"
 
static int getip(char *netif, char *ip, int len)
{
    struct ifaddrs *ifaddr, *ifa;
    int ret = -1;
    
    getifaddrs(&ifaddr);
    ifa = ifaddr;

    while (ifa) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
            printf("%s: %s\n", ifa->ifa_name, inet_ntoa(pAddr->sin_addr));

            if (0 == strcmp(netif, ifa->ifa_name)) {
                printf("%s=%s\n", netif, inet_ntoa(pAddr->sin_addr));
                strncpy(ip, inet_ntoa(pAddr->sin_addr), len);
                ret = 0;  
                break;
            }
        }
        ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaddr);
    return ret;
}
/* holder for curl fetch */
struct curl_fetch_st {
    char *payload;
    size_t size;
};

/* callback for curl fetch */
static size_t curl_callback(void *contents, size_t size, size_t nmemb, void *userp) 
{
    size_t realsize = size * nmemb;                             /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

    //printf("%s %p\n", __func__, userp);
    /* expand buffer */
    p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) {
      /* this isn't good */
      fprintf(stderr, "ERROR: Failed to expand buffer in %s", __func__);
      /* free buffer */
      free(p->payload);
      /* return */
      return -1;
    }

    /* copy contents to buffer */
    memcpy(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    /* ensure null termination */
    p->payload[p->size] = 0;

    /* return size */
    return realsize;
}

static int postip(char *url)
{
    char ip[16];
    char hostname[HOST_NAME_MAX];

    json_object *json;
    json_object *retobj;
    enum json_tokener_error jerr = json_tokener_success;

    CURL *ch;                                               /* curl handle */
    CURLcode rcode;
    struct curl_slist *headers = NULL;
    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch;                 /* pointer to fetch struct */

    memset(ip, 0, sizeof(ip));   
    getip(NETIFNAME, ip, sizeof(ip) - 1);

    cf->size = 0;
    cf->payload = (char *) calloc(1, sizeof(cf->payload));

    if (cf->payload == NULL) {
        syslog(LOG_ERR, "Failed to allocate payload in curl_fetch_url");
        return -1;
    }

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to create curl handle in fetch_session");
        /* return error */
        return 1;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    json = json_object_new_object();
    json_object_object_add(json, "command", json_object_new_string("report_status"));
    json_object_object_add(json, "token", json_object_new_string("d53fd9852538440c926765dd69927a2c"));
    json_object_object_add(json, "machine_ip", json_object_new_string(ip));
    json_object_object_add(json, "use_status", json_object_new_string("1"));

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        printf("gethostname failed with %d\n", errno);
    }

    json_object_object_add(json, "hardware_no", json_object_new_string(hostname));

    
    printf("json='%s', len=%lu\n", json_object_to_json_string(json), strlen(json_object_to_json_string(json)));
    printf("url=%s\n", url);

    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(json));
    
    /* set url to fetch */
    curl_easy_setopt(ch, CURLOPT_URL, url);

    /* set calback function */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) cf);

    /* set default user agent */
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* set timeout */
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 5);

    /* enable location redirects */
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);

    /* set maximum allowed redirects */
    curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1);
    curl_easy_setopt(ch, CURLOPT_VERBOSE, 1L);

    /* fetch the url */
    rcode = curl_easy_perform(ch);


    //rcode = curl_fetch_url(ch, url, cf);
    curl_easy_cleanup(ch);
    curl_slist_free_all(headers);
    if (json != NULL) {
        printf("Free JSON\n");
        json_object_put(json);
    }

    if (rcode != CURLE_OK || cf->size < 1) {
            /* log error */
            syslog(LOG_ERR, "Failed to fetch url (%s) '%s'",
                url, curl_easy_strerror(rcode));
            /* return error */
            return 2;
     }

    /* check payload */
    if (cf->payload != NULL) {
        /* print result */
        printf("CURL Returned: %s len=%lu\n", cf->payload, strlen(cf->payload));
        /* parse return */
        json = json_tokener_parse(cf->payload); //json_tokener_parse_verbose(cf->payload, &jerr);
        /* free payload */
        free(cf->payload);
    } else {
        /* error */
        syslog(LOG_ERR, "Failed to populate payload");
        /* free payload */
        free(cf->payload);
        /* return */
        return 3;
    }

    /* check error */
    if (json == NULL) {
        /* error */
        syslog(LOG_ERR, "ERROR: Failed to parse json string");
        /* free json object */
        json_object_put(json);
        /* return */
        return 4;
    }

    /* debugging */
    printf("Parsed JSON: %s\n", json_object_to_json_string(json));

    json_object_object_get_ex(json, "ip", &retobj);
    printf("JsonIP=%s\n", json_object_get_string(retobj));

    json_object_object_get_ex(json, "date", &retobj);
    printf("JsonDate=%s\n", json_object_get_string(retobj));    

    if (json != NULL) {
        printf("Free JSON\n");
        json_object_put(json);
    }

    return 0;

}

int main()
{
    int ret = 0;
    openlog("Client", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_NOTICE, "Client built %s %s started", __DATE__, __TIME__);
    

    ret = postip(SERVERURL);

    return 0;

    closelog();
}

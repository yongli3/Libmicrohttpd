/*
     This file is part of libmicrohttpd
     Copyright (C) 2007 Christian Grothoff (and other contributing authors)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
/**
 * @file minimal_example.c
 * @brief minimal example for how to use libmicrohttpd
 * @author Christian Grothoff
 */

#include "platform.h"
#include <microhttpd.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <json-c/json.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>

#define PAGE "<html><head><title>X1000</title></head><body>X1000</body></html>"

struct postStatus {
    bool status;
    char *buff;
};

#if 0
MHD_set_connection_value kind=1 key=[HOST] value=[10.239.48.155:8080]
MHD_set_connection_value kind=1 key=[accept] value=[application/json]
MHD_set_connection_value kind=1 key=[accept-encoding] value=[gzip, deflate]
MHD_set_connection_value kind=1 key=[accept-language] value=[en-US,en;q=0.8]
MHD_set_connection_value kind=1 key=[user-agent] value=[Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36]
MHD_set_connection_value kind=1 key=[content-type] value=[application/json]
MHD_set_connection_value kind=1 key=[connection] value=[close]
MHD_set_connection_value kind=1 key=[content-length] value=[5]
+ahc_echo method=POST url=/ version=HTTP/1.1
+ahc_echo method=POST url=/ version=HTTP/1.1
ahc_echo size=5 data={a:b}
+ahc_echo method=POST url=/ version=HTTP/1.1
Post data: {a:b}
#endif

static int getIP(char *netif, char *ip, int len)
{
    struct ifaddrs *ifaddr, *ifa;

    getifaddrs(&ifaddr);
    ifa = ifaddr;

    while (ifa) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
            printf("%s: %s\n", ifa->ifa_name, inet_ntoa(pAddr->sin_addr));

            if (0 == strcmp(netif, ifa->ifa_name)) {
                //json_object_object_add(jobj,"ip", json_object_new_string(inet_ntoa(pAddr->sin_addr)));
                
                break;
            }
        }
        ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaddr);
    return 0;
}

static int sendpost()
{
    return 0;
}

static int generate_json(json_object *jobj) 
{
    char *ip = "255.255.255.255"
    char *netif = "enp2s0";
    char *method = "post";  
    struct tm *timeinfo;
    struct timeval curtime;
    struct ifaddrs *ifaddr, *ifa;    
    int milli;
    char buffer[32];
    char iso8601[32];
    char *pch;
      
    if (NULL == jobj) {
        return -1;
    }
    
	json_object_object_add(jobj,"method", json_object_new_string(method));
	json_object_object_add(jobj,"id", json_object_new_int(100));

    gettimeofday(&curtime, NULL);
    milli = curtime.tv_usec / 1000;

    timeinfo = localtime(&curtime.tv_sec);
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S%z", timeinfo);
    printf("Current local time and date: [%s]\n", buffer);

    pch = strtok(buffer, "+");
    printf("pch=%s\n", pch);
    sprintf(iso8601, "%s.%d", pch, milli);
    
    pch = strtok(NULL, "+");
    printf("pch=%s\n", pch);
    sprintf(iso8601, "%s+%s", iso8601, pch);
    // 2016-08-01T13:16:30+0800
    printf("Current local time and date: [%s]\n", iso8601);
    json_object_object_add(jobj,"date", json_object_new_string(iso8601));

    // Get IP addr
    getifaddrs(&ifaddr);
    ifa = ifaddr;

    while (ifa) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
            printf("%s: %s\n", ifa->ifa_name, inet_ntoa(pAddr->sin_addr));

            if (0 == strcmp(netif, ifa->ifa_name)) {
                json_object_object_add(jobj,"ip", json_object_new_string(inet_ntoa(pAddr->sin_addr)));
                break;
            }
        }
        ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaddr);

    // check IP
    printf("JsonIP=%s\n", json_object_get_string(json_object_object_get(jobj, "ip")));

	const char *json_string = json_object_to_json_string(jobj);
	printf ("The json object created: '%s' len=%d\n", json_string, strlen(json_string));

    return jobj;
    //json_object *recv_json = json_tokener_parse(recv_json_string);
	//json_object_get_string(json_object_object_get(recv_json, "result"))
}

static void get_ip_str(const struct sockaddr *sa, char *ip_str)
{
    if(sa)
    {
        getnameinfo(sa, sizeof (struct sockaddr), ip_str, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    }
}

static short get_port(const struct sockaddr* sa)
{
    if(sa)
    {
        switch(sa->sa_family)
        {
            case AF_INET:
                return ((struct sockaddr_in *)sa)->sin_port;
            case AF_INET6:
                return ((struct sockaddr_in *)sa)->sin_port;
            default:
                return 0;
        }
    }
    return 0;
}

static int
ahc_echo(void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size, void **ptr)
{
  static int aptr;
  const char *me = cls;
  struct MHD_Response *response;
  int ret;
  char ip_str[36];
  unsigned short ip_port;
  char *json_str = NULL;
  json_object *jobj = NULL;

  union MHD_ConnectionInfo * conninfo = MHD_get_connection_info(
            connection,
            MHD_CONNECTION_INFO_CLIENT_ADDRESS
    );

  printf("+%s me=%s method=%s url=%s version=%s ptr=%p *ptr=%p upload_data=%s size=%d ", 
    __func__, me, method, url, version, ptr, *ptr, upload_data, *upload_data_size);

    get_ip_str(conninfo->client_addr, ip_str);

    ip_port = get_port(conninfo->client_addr);

  printf(" IP=%s port=%d\n", ip_str, ip_port);

  struct postStatus *post = NULL;
  post = (struct postStatus*)*ptr;

#if 1
 if(post == NULL) {
    printf("post=NULL\n");
    post = malloc(sizeof(struct postStatus));
    post->status = false;
    post->buff = NULL;
    *ptr = post;
  } 

 if(!post->status) {
    printf("set status=true!\n");
    post->status = true;
    return MHD_YES;
  } else {// status = true;
    if(*upload_data_size != 0) {
        printf("%s size=%d data=%s\n", __func__, *upload_data_size, upload_data);
        post->buff = malloc(*upload_data_size + 1);
        
        snprintf(post->buff, *upload_data_size + 1,"%s",upload_data);
        *upload_data_size = 0;
        return MHD_YES;
    } else {
        printf("Get Postdata: '%s' size=%d\n",post->buff, strlen(post->buff));
        // Get all post data and process the commands
        // return json string
        
        if(post->buff != NULL)
            free(post->buff);
    }
  } 

  if(post != NULL)
    free(post);

#else
  if (0 != strcmp (method, "GET"))
    return MHD_NO;              /* unexpected method */
  if (&aptr != *ptr)
    {
      /* do never respond on first call */
      *ptr = &aptr;
      return MHD_YES;
    }
  *ptr = NULL;                  /* reset when done */
#endif
    jobj = json_object_new_object();
    generate_json(jobj);

    json_str = json_object_to_json_string(jobj);
    
    printf("Returning JSON str via http: '%s' size=%d\n", json_str, strlen(json_str));

  response = MHD_create_response_from_buffer(strlen(json_str),
					      (void *) json_str,
					      MHD_RESPMEM_MUST_COPY);
  MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
  
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  json_object_put(jobj);
  return ret;
}

#if 0
struct ConnectionData
{
        bool is_parsing;
        stringstream read_post_data;
};
 
 
int handle_request(void *cls, struct MHD_Connection *connection,
                   const char *url,
                   const char *method, const char *version,
                   const char *upload_data,
                   size_t *upload_data_size, void **con_cls)
{
        int http_code;
        string output;
        string content_type = "text/plain";
       
        if (strcmp(method, MHD_HTTP_METHOD_POST) == 0)
        {
                ConnectionData* connection_data = NULL;
               
                connection_data = static_cast<ConnectionData*>(*con_cls);
                if (NULL == connection_data)
                {
                        connection_data = new ConnectionData();
                        connection_data->is_parsing = false;
                        *con_cls = connection_data;
                }
               
                if (!connection_data->is_parsing)
                {
                        // First this method gets called with *upload_data_size == 0
                        // just to let us know that we need to start receiving POST data
                        connection_data->is_parsing = true;
                        return MHD_YES;
                }
                else
                {
                        if (*upload_data_size != 0)
                        {
                                // Receive the post data and write them into the bufffer
                                connection_data->read_post_data << string(upload_data, *upload_data_size);
                                *upload_data_size = 0;
                                return MHD_YES;
                        }
                        else
                        {
                                // *upload_data_size == 0 so all data have been received
                                output = "Received data:\n\n";
                                output += connection_data->read_post_data.str();
                               
                                delete connection_data;
                                connection_data = NULL;
                                *con_cls = NULL;
                        }
                }
        }
        else
        {
                http_code = MHD_HTTP_NOT_FOUND;
                content_type = "text/plain";
                output = "Unknown request method";
        }
 
        const char* output_const = output.c_str();
 
        struct MHD_Response *response = MHD_create_response_from_buffer(
                                        strlen(output_const), (void*)output_const, MHD_RESPMEM_MUST_COPY);
 
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, content_type.c_str());
 
        int ret = MHD_queue_response(connection, http_code, response);
 
        MHD_destroy_response(response);
       
        return ret;
}
#endif

int
main (int argc, char *const *argv)
{
  struct MHD_Daemon *d;

    printf("%s-%s\n", __DATE__, __TIME__);

  if (argc != 2)
    {
      printf ("%s PORT\n", argv[0]);
      return 1;
    }
       //MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
		//&answer_to_connection, NULL, MHD_OPTION_END);
    
  d = MHD_start_daemon (// MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | MHD_USE_POLL,
			MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG,
			// MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG | MHD_USE_POLL,
			// MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG,
                        atoi (argv[1]),
                        NULL, NULL, &ahc_echo, PAGE,
			MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
			MHD_OPTION_END);
  if (d == NULL)
    return 1;
  (void) getc (stdin);
  MHD_stop_daemon (d);
  return 0;
}

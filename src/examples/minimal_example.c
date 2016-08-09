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

//#include "platform.h"
#include <microhttpd.h>
#include <stdbool.h>
#include <syslog.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <json-c/json.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <unistd.h>

#include <curl/curl.h>

#define PAGE "<html><head><title>X1000</title></head><body>X1000</body></html>"
#define debug(...) _debug(__BASE_FILE__, __LINE__, __VA_ARGS__)

//bool stophttp = false;

sem_t stopsem;

struct postStatus {
    bool status;
    char *buff;
};

struct curl_fetch_st {
    char *payload;
    size_t size;
};

typedef struct {
    char configfile[64];
    int daemon;
    int debuglevel;
    int port;
    int interval;    
    char ifname[16];
    char serverurl[64];
} s_config;

static s_config config;

static void _debug(const char filename[], int line, int level, const char *format, ...)
{
    va_list vlist;

    if (config.debuglevel >= level) {
        openlog("Client", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    	va_start(vlist, format);
    	vsyslog(level, format, vlist);
        va_end(vlist);
        closelog();
    }
}

static void config_init() 
{
    strncpy(config.configfile, "/etc/client.conf", sizeof(config.configfile) - 1);
    config.daemon = 1;
    config.debuglevel = LOG_DEBUG;
    config.port = 8080;
    config.interval = 20;
    strncpy(config.serverurl, "http://localhost:8080/", sizeof(config.serverurl) - 1);
    strncpy(config.ifname, "eth0", sizeof(config.ifname) - 1);
}

static void config_dump() 
{
    debug(LOG_DEBUG, "conffile=%s serverurl=%s ifname=%s", 
        config.configfile, config.serverurl, config.ifname);

    debug(LOG_DEBUG, "daemon=%d debuglevel=%d port=%d interval=%d", 
        config.daemon, config.debuglevel, config.port, config.interval);
}

static s_config *config_get_config(void)
{
	return &config;
}

static void usage() 
{
    printf("Usage:\n");
    printf("-c config file name \n");
    printf("-f Run in foreground \n");
    printf("-i set network name \n");
    printf("-d set debug level \n");
    printf("-t set post thread interval time\n");
    printf("-u set server URL\n");      
    printf("-v print version\n");
    printf("\n");
    return;
}

static int set_log_level(int level)
{
	config.debuglevel = level;
	return 0;
}

static void parse_commandline(int argc, char **argv)
{
	int c;

	s_config *config = config_get_config();

	while (-1 != (c = getopt(argc, argv, "c:hfd:t:u:vi:"))) {

		switch(c) {

    		case 'h':
    			usage();
    			exit(1);
    			break;

    		case 'c':
    			if (optarg) {
    				strncpy(config->configfile, optarg, sizeof(config->configfile) - 1);
    			}
    			break;

    		case 'i':
    			if (optarg) {
    				strncpy(config->ifname, optarg, sizeof(config->ifname) - 1);
    			}
    			break;

    		case 'f':
    			config->daemon = 0;
    			break;

    		case 'd':
    			if (optarg) {
    				set_log_level(atoi(optarg));
    			}
    			break;
                
    		case 't':
    			if (optarg) {
    				config->interval = atoi(optarg);
    			}
    			break;

            case 'u':
                if (optarg) {
                    strncpy(config->serverurl, optarg, sizeof(config->serverurl) - 1);
                }
                break;

    		case 'v':
    			printf("This is version " __DATE__ "\n");
    			exit(1);
    			break;

    		default:
    			usage();
    			exit(1);
    			break;
		}
	}
}

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

static pid_t safe_fork(void)
{
	pid_t result;
	result = fork();

	if (result == -1) {
		debug(LOG_CRIT, "Failed to fork: %s. Bailing out", strerror(errno));
		abort();
	} else if (result == 0) {
		/* I'm the child - do some cleanup */
	}

	return result;
}

static void sigchld_handler(int s)
{
	int	status;
	pid_t rc;

	debug(LOG_DEBUG, "SIGCHLD handler: Trying to reap a child");

	rc = waitpid(-1, &status, WNOHANG | WUNTRACED);

	if(rc == -1) {
		if(errno == ECHILD) {
			debug(LOG_DEBUG, "SIGCHLD handler: waitpid(): No child exists now.");
		} else {
			debug(LOG_ERR, "SIGCHLD handler: Error reaping child (waitpid() returned -1): %s", strerror(errno));
		}
		return;
	}

	if(WIFEXITED(status)) {
		debug(LOG_DEBUG, "SIGCHLD handler: Process PID %d exited normally, status %d", (int)rc, WEXITSTATUS(status));
		return;
	}

	if(WIFSIGNALED(status)) {
		debug(LOG_DEBUG, "SIGCHLD handler: Process PID %d exited due to signal %d", (int)rc, WTERMSIG(status));
		return;
	}

	debug(LOG_DEBUG, "SIGCHLD handler: Process PID %d changed state, status %d not exited, ignoring", (int)rc, status);
	return;
}

static void termination_handler(int s)
{
	static	pthread_mutex_t	sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;

	debug(LOG_NOTICE, "%s Handler for termination caught signal %d", __func__, s);

#if 0
	/* Makes sure we only call fw_destroy() once. */
	if (pthread_mutex_trylock(&sigterm_mutex)) {
		debug(LOG_INFO, "Another thread already began global termination handler. I'm exiting");
		pthread_exit(NULL);
	} else {
		debug(LOG_INFO, "Cleaning up and exiting");
	}
#endif

	//debug(LOG_INFO, "Flushing...");
	//fw_destroy();

#if 0
	/* XXX Hack
	 * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
	 * termination handler) from happening so we need to explicitly kill the threads
	 * that use that
	 */
	if (tid_client_check) {
		debug(LOG_INFO, "Explicitly killing the fw_counter thread");
		pthread_kill(tid_client_check, SIGKILL);
	}
#endif

	debug(LOG_NOTICE, "Exiting & send stopsem...");
    //stophttp = true;
    sem_post(&stopsem);
	//exit(s == 0 ? 1 : 0);
	return;
}


static void init_signals(void)
{
	struct sigaction sa;

	debug(LOG_DEBUG, "Setting SIGCHLD handler to sigchld_handler()");
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGPIPE */
	/* This is done so that when libhttpd does a socket operation on
	 * a disconnected socket (i.e.: Broken Pipes) we catch the signal
	 * and do nothing. The alternative is to exit. SIGPIPE are harmless
	 * if not desirable.
	 */
	debug(LOG_DEBUG, "Setting SIGPIPE  handler to SIG_IGN");
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	debug(LOG_DEBUG, "Setting SIGTERM,SIGQUIT,SIGINT  handlers to termination_handler()");
	sa.sa_handler = termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	/* Trap SIGTERM */
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGQUIT */
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGINT */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}
}

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

static int generate_json(json_object *jobj) 
{
    json_object *retobj;
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
    json_object_object_get_ex(jobj, "ip", &retobj);
    printf("JsonIP=%s\n", json_object_get_string(retobj));

	const char *json_string = json_object_to_json_string(jobj);
	printf ("The json object created: '%s' len=%lu\n", json_string, strlen(json_string));

    return 0;
    //json_object *recv_json = json_tokener_parse(recv_json_string);
	//json_object_get_string(json_object_object_get(recv_json, "result"))
}

static void get_ip_str(const struct sockaddr *sa, char *ip_str)
{
    if(sa) {
        getnameinfo(sa, sizeof (struct sockaddr), ip_str, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    }
}

static short get_port(const struct sockaddr* sa)
{
    if(sa) {
        switch(sa->sa_family) {
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
  const char *json_str = NULL;
  json_object *jobj = NULL;

  const union MHD_ConnectionInfo * conninfo = MHD_get_connection_info(
            connection,
            MHD_CONNECTION_INFO_CLIENT_ADDRESS
    );

  printf("+%s me=%s method=%s url=%s version=%s ptr=%p *ptr=%p upload_data=%s size=%lu ", 
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
        printf("%s size=%lu data=%s\n", __func__, *upload_data_size, upload_data);
        post->buff = malloc(*upload_data_size + 1);
        
        snprintf(post->buff, *upload_data_size + 1,"%s",upload_data);
        *upload_data_size = 0;
        return MHD_YES;
    } else {
        printf("Get Postdata: '%s' size=%lu\n",post->buff, strlen(post->buff));
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
    
    printf("Returning JSON str via http: '%s' size=%lu\n", json_str, strlen(json_str));

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

static int httpserver()
{
    struct MHD_Daemon *d;

    debug(LOG_NOTICE, "+%s on port %d\n", __func__, config.port);

        //MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
		//&answer_to_connection, NULL, MHD_OPTION_END);
    
  d = MHD_start_daemon (// MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | MHD_USE_POLL,
			MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG,
			// MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG | MHD_USE_POLL,
			// MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG,
                        config.port,
                        NULL, NULL, &ahc_echo, PAGE,
			MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
			MHD_OPTION_END);
  if (d == NULL) {
        debug(LOG_ERR, "start fail!");
        return 1;
   }

  // FIXME create a libcurl client thread to post data to a resful server repeatly, and 
  //pthread_join() to wait for it forever

    debug(LOG_DEBUG, "wait for stopsem...");
    sem_wait(&stopsem);

#if 0 
    while (!stophttp) {
        //debug(LOG_DEBUG, "stophttp=%d", stophttp);
        sleep(1);
    }
#endif    
    debug(LOG_NOTICE, "receive stopsem & stop httpserver...");
    MHD_stop_daemon(d);
    return 0;
}

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

    getIP(config.ifname, ip, sizeof(ip) - 1);

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

// send http post to server
static void *postthreadfunc(void *arg)
{
    debug(LOG_DEBUG, "+%s", __func__);
    char *p = NULL;
    while (1) {
        debug(LOG_DEBUG, "%s sleep %d", __func__, config.interval);  
        postip(config.serverurl);
        sleep(config.interval);
    }

    debug(LOG_DEBUG, "-%s", __func__);    
    return NULL;
}

int main(int argc, char  **argv)
{
    int ret = 0;
    pthread_t  postthread;

    if (sem_init(&stopsem, 0, 0) == -1) {
        debug(LOG_ERR, "sem_init");
    }
    
    init_signals();

    config_init();

    config_dump();
    debug(LOG_NOTICE, "Client Built on %s-%s", __DATE__, __TIME__);

    parse_commandline(argc, argv);

    config_dump();

    ret = pthread_create(&postthread, 0 , postthreadfunc, NULL);
    if ( 0 != ret) {
        debug(LOG_ERR, "therea create fail %d", ret);    
        return -1;
    }

	pthread_detach(postthread);

    debug(LOG_DEBUG, "start process for httpserver daemon=%d", config.daemon);
	if (config.daemon) {
		debug(LOG_NOTICE, "Starting as daemon, forking to background");

		switch(safe_fork()) {
		case 0: /* child */
			setsid();
			httpserver();
			break;

		default: /* parent */
            debug(LOG_NOTICE, "parent exit...");
			exit(0);
			break;
		}
	} else {
		httpserver();
	}

    sem_destroy(&stopsem);
    debug(LOG_NOTICE, "main return 0...");
	return(0); /* never reached */
}

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

/*
curl --connect-timeout 200 -m 200 --keepalive-time 200 -vvv -H "Content-Type: application/json" -H "accept: application/json" -X POST -d '{"command":"get_gap","sign":"d53fd9852538440c926765dd69927a2c","hardware_no":"hd11234213","machine_ip":"192.168.0.1","use_status":"0"}' http://localhost:8080/
curl -vvv -H "Connection: Close" -H "Content-Type: application/json" -H "accept: application/json" -X POST -d '{"gap_no":"A0001AGAP001","sign":"e9f632f43d2344549bfb434f228cbe75","water_time":10,"command":"pour"}' http://10.239.48.166:8080/
curl -vvv -H "Connection: Close" -H "Content-Type: application/json" -H "accept: application/json" -X POST -d '{"gap_no":"A0001AGAP001","sign":"e9f632f43d2344549bfb434f228cbe75","water_time":10,"command":"get_gap"}' http://10.239.48.166:8080/

*/


//#include "platform.h"
#include <microhttpd.h>
#include <stdbool.h>
#include <syslog.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
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
#include <sys/syscall.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <math.h>

#include <curl/curl.h>
#include <sqlite3.h>

#define MAX_POUR_TIME_SECONDS   (150)
#define POUR_GPIO       (10)
#define SYSFS_GPIO_DIR "/sys/class/gpio"
#define MAX_BUF (64)

#define MAX_RECV (1024)
#define PAGE "<html><head><title>X1000</title></head><body>X1000</body></html>"
#define debug(...) _debug(__BASE_FILE__, __LINE__, __VA_ARGS__)

#define HARDWARE_STORAGE_ERROR  ("300")
#define HARDWARE_STORAGE_NORMAL  ("301")
#define HARDWARE_NETWORK_ERROR  ("400")
#define HARDWARE_NETWORK_NORMAL  ("401")
#define HARDWARE_DEVICE_ERROR  ("500")
#define HARDWARE_DEVICE_NORMAL  ("501")

// JSON/HTTP result
#define RESULT_NORMAL           ("0")
#define RESULT_ABNORMAL         ("1")

#define USE_STATUS_NORMAL       ("1")
#define USE_STATUS_OFF          ("2")
#define USE_STATUS_PROCESSING   ("3")
#define USE_STATUS_ABNORMAL     ("4")

#define CHARGING_TYPE_COUNT     ("1")
#define CHARGING_TYPE_PERIOD    ("2")

#define DEFAULT_POUR_TIMEOUT    ("30")
#define DEFAULT_REPORT_TIMEOUT  ("600")

#define COMMANDNAME_REPORT_STATUS  ("report_status")
#define COMMANDNAME_REPORT_WATER  ("report_water")

#define KEYNAME_CHARGING_TYPE  ("charging_type")
#define KEYNAME_CHARGING_TIME_S  ("charging_time_s")
#define KEYNAME_CHARGING_TIME_E  ("charging_time_e")
#define KEYNAME_USE_STATUS          ("use_status")
#define KEYNAME_POUR_TIMEOUT        ("pour_timeout")
#define KEYNAME_SERVER_URL          ("server_url")
#define KEYNAME_REPORT_TIME         ("report_time")

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
    char dbfile[32];
    char configfile[32];
    int daemon;
    int debuglevel;
    int port;
    int interval;    
    char ifname[16];
    char serverurl[64];
} s_config;

static s_config config;
static unsigned char signkey[33] = "d53fd9852538440c926765dd69927a2c";
static unsigned char *master_sign = "d53fd9852538440c926765dd69927a2c";

static unsigned char g_server_url[64];
static unsigned char g_gap_no[32];

static unsigned char g_device_status[32];
static unsigned char g_result[2];
static unsigned char g_errorcode[32];
static unsigned char g_use_status[2];
static unsigned char g_charging_type[2];
static unsigned char g_charging_time_s[13];
static unsigned char g_charging_time_e[13];
static unsigned char g_water_processing = 0;
static unsigned char  g_pour_timeout[4];
static unsigned char  g_ipcheck_time[4];
int g_water_time;

//static unsigned char g_dbname[32];

static pthread_mutex_t processing_mutex;

//pthread_mutex_init pthread_mutex_lock(processing_mutex)

//pthread_cond_wait

static void _debug(const char filename[], int line, int level, const char *format, ...)
{
    va_list vlist;

    va_start(vlist, format);
    vfprintf(stderr, format, vlist);
    fprintf(stderr, "\n");
    va_end(vlist);

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
    snprintf(config.dbfile, sizeof(config.dbfile), "%s", "./client.db");
    strncpy(config.configfile, "/etc/client.conf", sizeof(config.configfile) - 1);
    config.daemon = 0;
    config.debuglevel = LOG_DEBUG;
    config.port = 8080;
    config.interval = 20; // IP checking
    strncpy(config.serverurl, "http://localhost:8080/", sizeof(config.serverurl) - 1);
    strncpy(config.ifname, "eth0", sizeof(config.ifname) - 1);
}

static void status_dump() 
{
    debug(LOG_DEBUG, "dbfile=%s conffile=%s serverurl=%s ifname=%s daemon=%d debuglevel=%d port=%d interval=%d", 
        config.dbfile, config.configfile, config.serverurl, config.ifname, 
        config.daemon, config.debuglevel, config.port, config.interval);
    return;
}

static void config_dump() 
{
    debug(LOG_DEBUG, "dbfile=%s conffile=%s serverurl=%s ifname=%s daemon=%d debuglevel=%d port=%d interval=%d", 
        config.dbfile, config.configfile, config.serverurl, config.ifname, 
        config.daemon, config.debuglevel, config.port, config.interval);
    return;
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

static int update_callback(void *data, int argc, char **argv, char **azColName){
   int i;
   fprintf(stdout, "+%s %s: ", __func__, (const char*)data);
   for(i=0; i<argc; i++){
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

static int set_data(char *key, char *value)
{
    sqlite3 *db = NULL;
    char *zErrMsg = 0;
    int  rc, ret;
    char sql[256];
    char *data = "";

    ret = -1;

    if (0 == strlen(config.dbfile)) {
        debug(LOG_ERR, "dbfile error!\n");
        return ret;
    }
    
    rc = sqlite3_open(config.dbfile, &db);
    if( rc ){
          fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
          return ret;
    }else{
          fprintf(stdout, "Opened database successfully\n");
    }

    snprintf(sql, sizeof(sql), "insert or replace into config (id, key, value) values ((select id from config where key=\"%s\"), \"%s\", \"%s\")", 
        key, key, value);

    rc = sqlite3_exec(db, sql, update_callback, (void*)data, &zErrMsg);
    if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);          
     }else{
        ret = 0;
        //fprintf(stdout, "Operation done successfully\n");
     }

    if (db)
        sqlite3_close(db);

    return ret;

}

static int select_callback(void *data, int argc, char **argv, char **azColName)
{
    int i;
   
    debug(LOG_DEBUG, "+%s\n", __func__);
 
   for(i=0; i<argc; i++){
      debug(LOG_DEBUG, "%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
      strcpy(data, argv[i]);
      break;
   }
   return 0;
}

static int get_data(char *key, char *value)
{
    sqlite3 *db = NULL;
    char *zErrMsg = 0;
    int  rc, ret;
    char sql[256];

    ret = -1;

    if (0 == strlen(config.dbfile)) {
        debug(LOG_ERR, "dbfile error!\n");
        return ret;
    }

    rc = sqlite3_open(config.dbfile, &db);
    if( rc ){
          debug(LOG_ERR, "Can't open database: %s\n", sqlite3_errmsg(db));
          return ret;
    }else{
          debug(LOG_DEBUG, "Opened database %s successfully\n", config.dbfile);
    }

    snprintf(sql, sizeof(sql), "select value from config where key = \"%s\"", key);
    debug(LOG_DEBUG, "exec sql [%s]\n", sql);
    rc = sqlite3_exec(db, sql, select_callback, (void*)value, &zErrMsg);
    if( rc != SQLITE_OK ){
       debug(LOG_ERR, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);         
    }else{
       //fprintf(stdout, "Operation done successfully value=[%s]\n", value);
       ret = 0;
    }  
    
    if (db)
        sqlite3_close(db);

    return ret;
}


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

// return 0 = find IP
static int get_ip(char *netif, char *ip, int len)
{
    struct ifaddrs *ifaddr, *ifa;
    int ret = -1;

    getifaddrs(&ifaddr);
    ifa = ifaddr;

    while (ifa) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
            debug(LOG_DEBUG, "netif=%s name=%s: IP=%s ifa=%p\n", 
                netif, ifa->ifa_name, inet_ntoa(pAddr->sin_addr), ifa);

            if (0 == strcmp(netif, ifa->ifa_name)) {
                strncpy(ip, inet_ntoa(pAddr->sin_addr), len -1);
                debug(LOG_DEBUG, "Get IP %s", ip);
                ret = 0;
                break;
            }
        }
        ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaddr);
    return ret;
}

static int check_ip()
{
    static char old_ip[16];
    static char ip[16];
    
    get_ip(config.ifname, ip, sizeof(ip));

    debug(LOG_DEBUG, "old_ip=%s ip=%s\n", old_ip, ip);
    if (strcmp(ip, old_ip)) {
        memcpy(old_ip, ip, sizeof(old_ip));
        return 1;
    } else {
        return 0;
    }
}

static int generate_json_error(json_object *jobj, int errorcode) 
{
    char error[4];  
    const char *json_string;
    
    if (NULL == jobj) {
        return -1;
    }

    snprintf(error, sizeof(error), "%d", errorcode);
    
	json_object_object_add(jobj,"error_code", json_object_new_string(error));
	json_string =
        json_object_to_json_string(jobj);
	debug(LOG_DEBUG, "The json object created: '%s' len=%lu\n", json_string, strlen(json_string));

    return 0;
}

static int gpio_export(unsigned int gpio)
{
	int fd, len;
	char buf[MAX_BUF];
 
	fd = open(SYSFS_GPIO_DIR "/export", O_WRONLY);
	if (fd < 0) {
		perror("gpio/export");
		return fd;
	}
 
	len = snprintf(buf, sizeof(buf), "%d", gpio);
	write(fd, buf, len);
	close(fd);
 
	return 0;
}

static int gpio_unexport(unsigned int gpio)
{
	int fd, len;
	char buf[MAX_BUF];
 
	fd = open(SYSFS_GPIO_DIR "/unexport", O_WRONLY);
	if (fd < 0) {
		perror("gpio/export");
		return fd;
	}
 
	len = snprintf(buf, sizeof(buf), "%d", gpio);
	write(fd, buf, len);
	close(fd);
	return 0;
}

static int gpio_set_dir(unsigned int gpio, unsigned int out_flag)
{
	int fd, len;
	char buf[MAX_BUF];
 
	len = snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR  "/gpio%d/direction", gpio);
 
	fd = open(buf, O_WRONLY);
	if (fd < 0) {
		perror("gpio/direction");
		return fd;
	}
 
	if (out_flag)
		write(fd, "out", 4);
	else
		write(fd, "in", 3);
 
	close(fd);
	return 0;
}

static int gpio_set_value(unsigned int gpio, unsigned int value)
{
	int fd, len;
	char buf[MAX_BUF];
 
	len = snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/value", gpio);
 
	fd = open(buf, O_WRONLY);
	if (fd < 0) {
		perror("gpio/set-value");
		return fd;
	}
 
	if (value)
		write(fd, "1", 2);
	else
		write(fd, "0", 2);
 
	close(fd);
	return 0;
}

static int gpio_get_value(unsigned int gpio, unsigned int *value)
{
	int fd, len;
	char buf[MAX_BUF];
	char ch;

	len = snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/value", gpio);
 
	fd = open(buf, O_RDONLY);
	if (fd < 0) {
		perror("gpio/get-value");
		return fd;
	}
 
	read(fd, &ch, 1);

	if (ch != '0') {
		*value = 1;
	} else {
		*value = 0;
	}
 
	close(fd);
	return 0;
}

static int gpio_set_edge(unsigned int gpio, char *edge)
{
	int fd, len;
	char buf[MAX_BUF];

	len = snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/edge", gpio);
 
	fd = open(buf, O_WRONLY);
	if (fd < 0) {
		perror("gpio/set-edge");
		return fd;
	}
 
	write(fd, edge, strlen(edge) + 1); 
	close(fd);
	return 0;
}

// polling gpio
static int gpio_poll(int gpio, int time_seconds)
{
    struct timespec spec;
    int left_ms = 0;
    int wait_ms = 0;
    unsigned int water_seconds;
    unsigned int total_ms;
    time_t last_pressed_second = 0;
    unsigned long last_pressed_millisecond = 0;
    time_t current_second = 0;
    unsigned long current_millisecond = 0;
    time_t last_second = 0;
    unsigned long last_millisecond = 0;    
    int fd, ret;
    char val[2], buf[MAX_BUF];
    unsigned char key_value, key_pressed, key_is_pressing;
    sigset_t emptyset;
    struct pollfd fds = {0};

    debug(LOG_DEBUG, "+%s %d-%d\n", __func__, gpio, time_seconds);

    gpio_export(gpio);
    gpio_set_dir(gpio, 0);
    gpio_set_edge(gpio, "both");
    
    snprintf(buf, sizeof(buf), SYSFS_GPIO_DIR "/gpio%d/value", gpio);
    fd = open(buf , O_RDONLY);
    debug(LOG_DEBUG, "path = %s fd = %d\n", buf, fd);

    fds.fd = fd;
    fds.events = POLLPRI;
    sigemptyset(&emptyset);
    total_ms = 0;
    key_is_pressing = 0;
    key_pressed = 0;
    water_seconds = time_seconds;
    left_ms = water_seconds * 1000;
    last_pressed_second = 0;    

    while ((total_ms < ((10+water_seconds)*1000)) && (left_ms > 0)) {
        //ret = fallback_ppoll(&fds, 1, 3000, &emptyset);
        clock_gettime(CLOCK_REALTIME, &spec);
        last_second = spec.tv_sec;
        last_millisecond = round(spec.tv_nsec / 1.0e6);
        wait_ms = left_ms;
        if ((wait_ms + total_ms) > ((10+water_seconds)*1000)) { 
            wait_ms = ((10+water_seconds)*1000) - total_ms;
        }
        debug(LOG_DEBUG, "**poll left=%d passed=%d wait=%d\n", left_ms, total_ms, wait_ms);
        ret = poll(&fds, 1, wait_ms);
        // get data or timeout or error
        if (0 == ret) { // timeout, no change on GPIO            
            total_ms += wait_ms;
            debug(LOG_DEBUG, "timeout %d-%d-%d ", wait_ms, left_ms, total_ms);
            lseek(fd, 0, SEEK_SET);
            if (read(fd, val, 2 * sizeof(char)) != 2)
                debug(LOG_DEBUG, "could not read value\n");
            else { // check gpio value
                key_value = strtol(val, NULL, 10); // 0 = pressed
                key_pressed = key_value ? 0:1;
                debug(LOG_DEBUG, "key %s\n", key_value ? "release":"pressed");
            }

            if (key_pressed) { // keep pressed & timeout
                debug(LOG_DEBUG, "MUST-STOP left=%d pressed_ms=%d\n", left_ms, wait_ms);
                left_ms -= wait_ms;
                break;
            }
            
        } else if (ret < 0) {
            debug(LOG_DEBUG, "error %s\n", strerror(errno));
            total_ms += 1000;
        } else {// get data
            clock_gettime(CLOCK_REALTIME, &spec);
            current_second = spec.tv_sec;
            current_millisecond = round(spec.tv_nsec / 1.0e6);
            total_ms = total_ms + (current_second - last_second) * 1000
                + (current_millisecond - last_millisecond);
            
            debug(LOG_DEBUG, "%d ret=%d response events: 0x%X ", key_is_pressing, ret, fds.revents);        
            lseek(fd, 0, SEEK_SET);
            if (read(fd, val, 2 * sizeof(char)) != 2)
                debug(LOG_DEBUG, "could not read value\n");
            else { // check gpio value
                key_value = strtol(val, NULL, 10);
                key_pressed = key_value ? 0:1;
                debug(LOG_DEBUG, "key %s\n", key_value ? "release":"pressed");
                if (key_pressed) {
                    if (0 == last_pressed_second) { // first time pressed
                        last_pressed_second = current_second;
                        last_pressed_millisecond = current_millisecond;
                        key_is_pressing = 1;
                    } else { // pressed not the first time
                        if (key_is_pressing) { // pressed->pressed
                            debug(LOG_DEBUG, "impossible pressed!\n"); // 
                        } else { // release->pressed
                            last_pressed_second = current_second;
                            last_pressed_millisecond = current_millisecond;
                            key_is_pressing = 1;
                        }
                    }
                } else { // key release
                    if (0 == last_pressed_second) { //no pressed
                        if (key_is_pressing) {// pressed->release
                            debug(LOG_DEBUG, "impossible p->r\n");
                        } else { // release->release
                            debug(LOG_DEBUG, "first released!\n");
                        }

                    } else {// pressed before
                        if (key_is_pressing) {//press->release
                            debug(LOG_DEBUG, "left_ms=%d pressed_ms=%lu\n", left_ms, 1000 * (current_second - last_pressed_second) 
                            + (current_millisecond - last_pressed_millisecond));
                            left_ms = left_ms - 
                           1000 * (current_second - last_pressed_second) 
                            - (current_millisecond - last_pressed_millisecond);
                        } else {//relase->release
                            debug(LOG_DEBUG, "impossible r->r\n");
                        }
                        //difftime                                                              
                    }
                    key_is_pressing = 0;
                }
            }
        }
    }

    debug(LOG_DEBUG, "total=%d left=%d\n", total_ms, left_ms);
    
    close(fd);

    gpio_unexport(gpio);
    debug(LOG_DEBUG, "-%s %d-%d return=%d\n", __func__, gpio, time_seconds, left_ms);    
    return left_ms;
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
      debug(LOG_ERR, "ERROR: Failed to expand buffer in %s", __func__);
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

// send result to server after processing POUT command
static int report_water(char *url, int water_time_second)
{
    unsigned char tmpkey[33];
    char str_time[32];
    char hostname[HOST_NAME_MAX];
    const char *recv_item = NULL;
    json_object *jobj;
    json_object *retobj;
    enum json_tokener_error jerr = json_tokener_success;

    CURL *ch;                                               /* curl handle */
    CURLcode rcode;
    struct curl_slist *headers = NULL;
    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch;                 /* pointer to fetch struct */

    snprintf(str_time, sizeof(str_time), "%d", (water_time_second));

    cf->size = 0;
    cf->payload = (char *) calloc(1, sizeof(cf->payload));

    if (cf->payload == NULL) {
        debug(LOG_ERR, "Failed to allocate payload in curl_fetch_url");
        return -1;
    }

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
        debug(LOG_ERR, "ERROR: Failed to create curl handle in fetch_session");
        /* return error */
        return 1;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    jobj = json_object_new_object();

    snprintf(tmpkey, sizeof(tmpkey), "%s", signkey);
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        debug(LOG_ERR, "gethostname failed with %d\n", errno);
    }

    json_object_object_add(jobj,"command", json_object_new_string(COMMANDNAME_REPORT_WATER));
    json_object_object_add(jobj,"sign", json_object_new_string(tmpkey));
    json_object_object_add(jobj,"hardware_no", json_object_new_string(hostname));
    //TODO get device use_status and hardware status
    json_object_object_add(jobj,"gap_no", json_object_new_string(g_gap_no));
    json_object_object_add(jobj,"water_time", json_object_new_string(str_time));
        
    debug(LOG_DEBUG, "json='%s', len=%lu\n", json_object_to_json_string(jobj), strlen(json_object_to_json_string(jobj)));
    debug(LOG_DEBUG, "url=%s\n", url);

    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(jobj));
    /* set timeout */
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, (long)155);
    
    /* set url to fetch */
    curl_easy_setopt(ch, CURLOPT_URL, url);

    /* set calback function */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) cf);

    /* set default user agent */
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");

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
    if (jobj != NULL) {
        debug(LOG_DEBUG, "Free JSON");
        json_object_put(jobj);
    }

    if (rcode != CURLE_OK || cf->size < 1) {
            /* log error */
            debug(LOG_ERR, "%s Failed to fetch url (%s) '%s'", __func__, 
                url, curl_easy_strerror(rcode));
            /* return error */
            return 2;
     }

    /* check payload */
    if (cf->payload != NULL) {
        /* print result */
        debug(LOG_DEBUG, "CURL Returned: %s len=%lu\n", cf->payload, strlen(cf->payload));
        /* parse return */
        jobj = json_tokener_parse(cf->payload); //json_tokener_parse_verbose(cf->payload, &jerr);
        /* free payload */
        free(cf->payload);
    } else {
        /* error */
        debug(LOG_ERR, "Failed to populate payload");
        /* free payload */
        free(cf->payload);
        /* return */
        return 3;
    }

    /* check error */
    if (jobj == NULL) {
        /* error */
        debug(LOG_ERR, "ERROR: Failed to parse json string");
        /* free json object */
        json_object_put(jobj);
        /* return */
        return 4;
    }

    /* debugging */
    debug(LOG_DEBUG, "%s Parsed JSON: %s\n", __func__, json_object_to_json_string(jobj));

    // TODO key checking
    json_object_object_get_ex(jobj, "sign", &retobj);
    recv_item = json_object_get_string(retobj);
    if (NULL == recv_item) {
        debug(LOG_ERR, "%s no new signkey\n", __func__);
        return 5;
    }

    if (0 != strcmp(recv_item, tmpkey)) {
         debug(LOG_ERR, "recv_sign %s != %s!", recv_item, tmpkey);
         return -1;       
    }

    if (jobj != NULL) {
        debug(LOG_DEBUG, "%s Free JSON\n", __func__);
        json_object_put(jobj);
    }

    return 0;
}

// thread control hardware for POUR
static void *pourthreadfunc(void *arg)
{
    int *water_time = (int *) arg;
    int fd, ret;
    unsigned char c;
    struct pollfd fdset;

    debug(LOG_DEBUG, "+%s water_time=%d %p", __func__, *water_time, arg);

    // TODO power on

    ret = gpio_poll(POUR_GPIO, *water_time);

    report_water(g_server_url, *water_time - ret/1000);

    pthread_mutex_lock(&processing_mutex);
    g_water_processing = 0;
    snprintf(g_use_status, sizeof(g_use_status), "%s", USE_STATUS_NORMAL);
    pthread_mutex_unlock(&processing_mutex);

    debug(LOG_DEBUG, "-%s water_time=%d", __func__, *water_time);    
    return NULL;
}

// business logic
// process restful commands, and return json string 
// return -1 if input options incorrect
static int process_logic(json_object *jobj, const char *recv_command, const char *recv_sign, json_object *recv_jobj) 
{
    json_object *retobj;
    char *netif = "enp2s0";
    char hostname[33];
    struct tm *timeinfo;
    struct timeval curtime;
    int milli, ret;
    int water_time;
    char buffer[32];
    //char iso8601[32];
    unsigned char start_pour;
    char ip[16];
    char *pch;;
    const char *json_string;
    const char *recv_item = NULL;
    pthread_t  pourthread;
    time_t t;

    debug(LOG_DEBUG, "+%s CMD=%s SIGN=%s", __func__, recv_command, recv_sign);
      
    if (NULL == jobj) {
        debug(LOG_ERR, "jobj = NULL!");
        return -1;
    }

    if (NULL == recv_command) {
        debug(LOG_ERR, "recv_command = NULL!");
        return -1;
    }

    if (NULL == recv_sign) {
         debug(LOG_ERR, "recv_sign = NULL!");
         return -1;
     }

    // signkey checking
    if (0 != strcmp(recv_sign, signkey)) {
         debug(LOG_ERR, "recv_sign %s != %s!", recv_sign, signkey);
         return -1;       
    }

    if (0 == strcmp(recv_command, COMMANDNAME_REPORT_STATUS)) { // local test only
        // TODO update signkey
        gethostname(hostname, sizeof(hostname));
    	json_object_object_add(jobj,"command", json_object_new_string(recv_command));
    	json_object_object_add(jobj,"sign", json_object_new_string(recv_sign));
        json_object_object_add(jobj,"newsign", json_object_new_string(master_sign));
    	json_object_object_add(jobj,"result", json_object_new_string(g_result));
        json_object_object_add(jobj,"error_code", json_object_new_string(""));
        json_object_object_add(jobj,"use_status", json_object_new_string(USE_STATUS_NORMAL));
        json_object_object_add(jobj,KEYNAME_CHARGING_TYPE, json_object_new_string(CHARGING_TYPE_COUNT));
        json_object_object_add(jobj,"charging_time_s", json_object_new_string(g_charging_time_s));
        json_object_object_add(jobj,"charging_time_e", json_object_new_string(g_charging_time_e));
        json_object_object_add(jobj,"pour_timeout", json_object_new_string(g_pour_timeout));
    } else if (0 == strcmp(recv_command, "get_detail")) { // query device status
   	    json_object_object_add(jobj,"command", json_object_new_string(recv_command));
    	json_object_object_add(jobj,"sign", json_object_new_string(recv_sign));
    	json_object_object_add(jobj,"result", json_object_new_string(g_result));
        json_object_object_add(jobj,"error_code", json_object_new_string(g_errorcode));
        gethostname(hostname, sizeof(hostname));
        json_object_object_add(jobj,"hardware_no", json_object_new_string(hostname));
        memset(ip, 0, sizeof(ip));
        get_ip(config.ifname, ip, sizeof(ip));
        json_object_object_add(jobj,"machine_ip", json_object_new_string(ip));
        json_object_object_add(jobj,"use_status", json_object_new_string(g_use_status));    
        json_object_object_add(jobj,KEYNAME_CHARGING_TYPE, json_object_new_string(g_charging_type));
        json_object_object_add(jobj,"charging_time_s", json_object_new_string(g_charging_time_s));
        json_object_object_add(jobj,"charging_time_e", json_object_new_string(g_charging_time_e));
        json_object_object_add(jobj,"report_time", json_object_new_string(DEFAULT_REPORT_TIMEOUT));
        json_object_object_add(jobj,"device_status", json_object_new_string(g_device_status));
        json_object_object_add(jobj,"pour_timeout", json_object_new_string(g_pour_timeout));
    } else if (0 == strcmp(recv_command, "get_gap")) {
        json_object_object_get_ex(recv_jobj, "gap_no", &retobj);
        recv_item = json_object_get_string(retobj);
        if (NULL == recv_item) {
            debug(LOG_ERR, "%s no gap_no\n", __func__);
            return -1;
        }
        if (0 != strcmp(recv_item, g_gap_no)) {
            debug(LOG_ERR, "%s %s!=%s\n", __func__, recv_item, g_gap_no);
            return -1;
        }
        
   	    json_object_object_add(jobj,"command", json_object_new_string(recv_command));
    	json_object_object_add(jobj,"sign", json_object_new_string(recv_sign));
    	json_object_object_add(jobj,"result", json_object_new_string(g_result));
        json_object_object_add(jobj,"error_code", json_object_new_string(g_errorcode));
        gethostname(hostname, sizeof(hostname));
        json_object_object_add(jobj,"hardware_no", json_object_new_string(hostname));
        json_object_object_add(jobj,"use_status", json_object_new_string(g_use_status));
        json_object_object_add(jobj,"gap_no", json_object_new_string(recv_item));
    } else if (0 == strcmp(recv_command, "change_status")) {
        // TODO save options to DB
        json_object_object_get_ex(recv_jobj, "server_url", &retobj);
        recv_item = json_object_get_string(retobj);
        if (NULL == recv_item) {
            debug(LOG_ERR, "%s no server_url\n", __func__);
            return -1;
        }
        snprintf(g_server_url, sizeof(g_server_url), "%s", recv_item);

        json_object_object_get_ex(recv_jobj, "token", &retobj);
        recv_item = json_object_get_string(retobj);
        if (NULL == recv_item) {
            debug(LOG_ERR, "%s no token\n", __func__);
            return -1;
        }
        snprintf(signkey, sizeof(signkey), "%s", recv_item);

        json_object_object_get_ex(recv_jobj, KEYNAME_CHARGING_TYPE, &retobj);
         recv_item = json_object_get_string(retobj);
         if (NULL == recv_item) {
             debug(LOG_ERR, "%s no charging_type\n", __func__);
             return -1;
         }
         snprintf(g_charging_type, sizeof(g_charging_type), "%s", recv_item);
         set_data(KEYNAME_CHARGING_TYPE, g_charging_type);

        json_object_object_get_ex(recv_jobj, "charging_time_s", &retobj);
         recv_item = json_object_get_string(retobj);
         if (NULL == recv_item) {
             debug(LOG_ERR, "%s no charging_time_s\n", __func__);
             return -1;
         }
        snprintf(g_charging_time_s, sizeof(g_charging_time_s), "%s", recv_item);
        set_data(KEYNAME_CHARGING_TIME_S, g_charging_time_s);
        
        json_object_object_get_ex(recv_jobj, "charging_time_e", &retobj);
         recv_item = json_object_get_string(retobj);
         if (NULL == recv_item) {
             debug(LOG_ERR, "%s no charging_time_e\n", __func__);
             return -1;
         }
        snprintf(g_charging_time_e, sizeof(g_charging_time_e), "%s", recv_item);
        set_data(KEYNAME_CHARGING_TIME_E, g_charging_time_e);
        
        json_object_object_get_ex(recv_jobj, "use_status", &retobj);
        recv_item = json_object_get_string(retobj);
        if (NULL == recv_item) {
            debug(LOG_ERR, "%s no use_status\n", __func__);
            return -1;
        }
        snprintf(g_use_status, sizeof(g_use_status), "%s", recv_item);         

        json_object_object_get_ex(recv_jobj, "pour_timeout", &retobj);
        recv_item = json_object_get_string(retobj);
        if (NULL == recv_item) {
            debug(LOG_ERR, "%s no pour_timeout\n", __func__);
            return -1;
        }
        snprintf(g_pour_timeout, sizeof(g_pour_timeout), "%s", recv_item);
        set_data(KEYNAME_POUR_TIMEOUT, g_pour_timeout);

  	    json_object_object_add(jobj,"command", json_object_new_string(recv_command));
    	json_object_object_add(jobj,"sign", json_object_new_string(recv_sign));
    	json_object_object_add(jobj,"result", json_object_new_string(g_result));
        json_object_object_add(jobj,"error_code", json_object_new_string(g_errorcode));
        gethostname(hostname, sizeof(hostname));
        json_object_object_add(jobj,"hardware_no", json_object_new_string(hostname));
    } else if (0 == strcmp(recv_command, "pour")) { // water processing
        json_object_object_get_ex(recv_jobj, "gap_no", &retobj);
        recv_item = json_object_get_string(retobj);
        if (NULL == recv_item) {
            debug(LOG_ERR, "%s no gap_no\n", __func__);
            return -1;
        }
        
        if (0 != strcmp(g_gap_no, recv_item)) {
            debug(LOG_ERR, "%s %s!=%s\n", __func__, g_gap_no, recv_item);
            return -1;
        }
        //snprintf(g_gap_no, sizeof(g_gap_no), "%s", recv_item);
        
        json_object_object_get_ex(recv_jobj, "water_time", &retobj);
        recv_item = json_object_get_string(retobj);
        if (NULL == recv_item) {
            debug(LOG_ERR, "%s no water_time\n", __func__);
            return -1;
        }
        water_time = atoi(recv_item);
        if ((water_time < 0) || (water_time > MAX_POUR_TIME_SECONDS)) {
            debug(LOG_ERR, "%s water_time out of range\n", __func__);
            return -1;
        }
        
        start_pour = 0;
        if (0 == strcmp(g_use_status, USE_STATUS_OFF)) {
            snprintf(g_result, sizeof(g_result), "%s", RESULT_ABNORMAL);
            snprintf(g_errorcode, sizeof(g_errorcode), "%s", "OFF");
            start_pour |= 1; 
        }

        if (0 == strcmp(g_charging_type, CHARGING_TYPE_PERIOD)) {
            t = time(NULL);
            timeinfo = localtime(&t);
            strftime(buffer, sizeof(buffer), "%Y%m%d%H%M", timeinfo);
            if ((strcmp(buffer, g_charging_time_e) >= 0) 
                || (strcmp(buffer, g_charging_time_s) <= 0)) {
                snprintf(g_result, sizeof(g_result), "%s", RESULT_ABNORMAL);
                snprintf(g_errorcode, sizeof(g_errorcode), "%s,%s", g_errorcode, "OFF");
                start_pour |= 2;
            }
        }

        if (g_water_processing) { // only support one 
            snprintf(g_result, sizeof(g_result), "%s", RESULT_ABNORMAL);
            snprintf(g_errorcode, sizeof(g_errorcode), "%s,%s", g_errorcode, "PROCESSING");
            start_pour |= 4;
        } 

        if (0 == start_pour) {// start thread
            pthread_mutex_lock(&processing_mutex);
            g_water_processing = 1;
            snprintf(g_use_status, sizeof(g_use_status), "%s", USE_STATUS_PROCESSING);
            pthread_mutex_unlock(&processing_mutex);
            snprintf(g_result, sizeof(g_result), "%s", RESULT_NORMAL);
            snprintf(g_errorcode, sizeof(g_errorcode), "%s", "");
            g_water_time = water_time;
            debug(LOG_DEBUG, "start POUR thread option=%d\n", g_water_time);
            ret = pthread_create(&pourthread, 0 , pourthreadfunc, &g_water_time);
            if ( 0 != ret) {
                debug(LOG_ERR, "therea create fail %d", ret);    
                return -1;
            }            
            pthread_detach(pourthread);
        }
        
  	    json_object_object_add(jobj,"command", json_object_new_string(recv_command));
    	json_object_object_add(jobj,"sign", json_object_new_string(recv_sign));
    	json_object_object_add(jobj,"result", json_object_new_string(g_result));
        json_object_object_add(jobj,"error_code", json_object_new_string(g_errorcode));
        gethostname(hostname, sizeof(hostname));
        json_object_object_add(jobj,"hardware_no", json_object_new_string(hostname));
        json_object_object_add(jobj,"gap_no", json_object_new_string(g_gap_no));
        json_object_object_add(jobj,"use_status", json_object_new_string(g_use_status));
        json_object_object_add(jobj,"device_status", json_object_new_string(g_device_status));
        //sleep(150);
    } else if (0 == strcmp(recv_command, COMMANDNAME_REPORT_WATER)) {// for local test
  	    json_object_object_add(jobj,"command", json_object_new_string(recv_command));
    	json_object_object_add(jobj,"sign", json_object_new_string(recv_sign));
    	json_object_object_add(jobj,"result", json_object_new_string(g_result));
        json_object_object_add(jobj,"error_code", json_object_new_string(g_errorcode));
    }
    else {
        debug(LOG_ERR, "command error: %s", recv_command);
    }
#if 0
    gettimeofday(&curtime, NULL);
    milli = curtime.tv_usec / 1000;

    timeinfo = localtime(&curtime.tv_sec);
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S%z", timeinfo);
    debug(LOG_DEBUG, "Current local time and date: [%s]\n", buffer);

    pch = strtok(buffer, "+");
    debug(LOG_DEBUG, "pch=%s\n", pch);
    sprintf(iso8601, "%s.%d", pch, milli);
    
    pch = strtok(NULL, "+");
    debug(LOG_DEBUG, "pch=%s\n", pch);
    sprintf(iso8601, "%s+%s", iso8601, pch);
    // 2016-08-01T13:16:30+0800
    debug(LOG_DEBUG, "Current local time and date: [%s]\n", iso8601);
    json_object_object_add(jobj,"date", json_object_new_string(iso8601));
#endif

	json_string = json_object_to_json_string(jobj);
	debug(LOG_DEBUG, "-%s CMD=%s JSON_NEW='%s' len=%lu\n", __func__, recv_command, json_string, strlen(json_string));

    return 0;
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

static int print_out_key(void *cls, enum MHD_ValueKind kind, const char *key,
               const char *value)
{
  debug(LOG_DEBUG, "HEADER:%s=%s\n", key, value);
  return MHD_YES;
}

// thread accept http request
static int http_callback(void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size, void **ptr)
{
    static int aptr;
    const char *me = cls;
    struct MHD_Response *response;
    const union MHD_ConnectionInfo * conninfo;
    int ret;
    char ip_str[36];
    unsigned short ip_port;
    const char *json_str = NULL;
    json_object *jobj = NULL;
    json_object *recv_json = NULL;
    json_object *retobj = NULL;
    int errorcode = 0;
    json_bool jret;
    int recv_length = 0;
    const char *recv_command;
    const char *recv_sign;
    const char *hdr;

    MHD_get_connection_values(connection, MHD_HEADER_KIND, print_out_key, NULL);

    conninfo = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    get_ip_str(conninfo->client_addr, ip_str);
    ip_port = get_port(conninfo->client_addr);
    debug(LOG_DEBUG, "+%s method=%s url=%s version=%s ptr=%p *ptr=%p upload_data=%s size=%lu RemoteIP=%s port=%d", 
        __func__, method, url, version, ptr, *ptr, upload_data, *upload_data_size, ip_str, ip_port);

    // Only accept POST
    if (0 != strcmp(method, MHD_HTTP_METHOD_POST)) {
       debug(LOG_ERR, "method=%s\n", method);
        response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_NOT_ACCEPTABLE, response);
        MHD_destroy_response(response);
        debug(LOG_ERR, "%s \n", __func__);
        return ret;        
    }

    // check http header
    hdr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_ACCEPT);

    if ((hdr == NULL) || (0 != strcmp (hdr, "application/json"))) {
        debug(LOG_ERR, "HEADER_ACCEPT=%s\n", hdr);
        response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_NOT_ACCEPTABLE, response);
        MHD_destroy_response(response);
        debug(LOG_ERR, "%s \n", __func__);
        return ret;
    }

    hdr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_TYPE);

    if ((hdr == NULL) || (0 != strcmp (hdr, "application/json"))) {
        debug(LOG_ERR, "CONTENT_TYPE=%s\n", hdr);
        response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_NOT_ACCEPTABLE, response);
        MHD_destroy_response(response);       
        debug(LOG_ERR, "%s \n", __func__);
        return ret;      
    }
    hdr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_LENGTH);

    if (hdr == NULL) {
        debug(LOG_ERR, "CONTENT_LENGTH=%s\n", hdr);
          response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
          ret = MHD_queue_response(connection, MHD_HTTP_NOT_ACCEPTABLE, response);
          MHD_destroy_response(response);
          return ret;
    }

    recv_length = atoi(hdr);

    if (recv_length > MAX_RECV) {
        debug(LOG_ERR, "CONTENT_LENGTH=%s\n", hdr);
           response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
           ret = MHD_queue_response(connection, MHD_HTTP_NOT_ACCEPTABLE, response);
           MHD_destroy_response(response);
        return ret;
    }
 
  struct postStatus *post = NULL;
  post = (struct postStatus*)*ptr;

#if 1
 if(post == NULL) {
    debug(LOG_DEBUG, "post=NULL\n");
    post = malloc(sizeof(struct postStatus));
    post->status = false;
    post->buff = NULL;
    *ptr = post;
  } 

 if(!post->status) {
    debug(LOG_DEBUG, "set status=true!\n");
    post->status = true;
    return MHD_YES;
  } else {// status = true;
    if(*upload_data_size != 0) {
        debug(LOG_DEBUG, "size=%lu recvdata=%s\n", *upload_data_size, upload_data);
        post->buff = malloc(*upload_data_size + 1);
        
        snprintf(post->buff, *upload_data_size + 1,"%s",upload_data);
        *upload_data_size = 0;
        return MHD_YES;
    } else {
        debug(LOG_DEBUG, "Postdata='%s' size=%lu\n",post->buff, strlen(post->buff));
        // Get all post data and process the commands
        recv_json = json_tokener_parse(post->buff);
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
    if (NULL == recv_json) {
        // return error to restful client
        generate_json_error(jobj, 1);      
    } else {
        debug(LOG_DEBUG, "%s recv_json='%s'\n", __func__, json_object_to_json_string(recv_json));
        jret = json_object_object_get_ex(recv_json, "command", &retobj);
        recv_command = json_object_get_string(retobj);
        jret = json_object_object_get_ex(recv_json, "sign", &retobj);
        recv_sign = json_object_get_string(retobj); 
       
        process_logic(jobj, recv_command, recv_sign, recv_json);
    }

    json_str = json_object_to_json_string(jobj);
    debug(LOG_DEBUG, "response_JSON via http: '%s' size=%lu\n", json_str, strlen(json_str));

    response = MHD_create_response_from_buffer(strlen(json_str),
	    (void *) json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
    MHD_add_response_header (response, MHD_HTTP_HEADER_CONNECTION, "close");    
    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    if (jobj != NULL)
        json_object_put(jobj);
    
    if (recv_json != NULL)
        json_object_put(recv_json);
    
    debug(LOG_DEBUG, "-%s %d", __func__, ret);
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

// send http POST to server report_status command
static int postip(char *url)
{
    unsigned char tmpkey[33];

    char ip[16];
    char hostname[HOST_NAME_MAX];
    const char *recv_item = NULL;
    json_object *jobj;
    json_object *retobj;
    enum json_tokener_error jerr = json_tokener_success;

    CURL *ch;                                               /* curl handle */
    CURLcode rcode;
    struct curl_slist *headers = NULL;
    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch;                 /* pointer to fetch struct */

    memset(ip, 0, sizeof(ip));   
    get_ip(config.ifname, ip, sizeof(ip));

    debug(LOG_DEBUG, "+%s ip=%s", __func__, ip);

    cf->size = 0;
    cf->payload = (char *) calloc(1, sizeof(cf->payload));

    if (cf->payload == NULL) {
        debug(LOG_ERR, "Failed to allocate payload in curl_fetch_url");
        return -1;
    }

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
        debug(LOG_ERR, "ERROR: Failed to create curl handle in fetch_session");
        /* return error */
        return 1;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    jobj = json_object_new_object();

    snprintf(tmpkey, sizeof(tmpkey), "%s", signkey);
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        debug(LOG_ERR, "gethostname failed with %d\n", errno);
    }
    json_object_object_add(jobj,"command", json_object_new_string(COMMANDNAME_REPORT_STATUS));
    json_object_object_add(jobj,"sign", json_object_new_string(tmpkey));
    json_object_object_add(jobj,"hardware_no", json_object_new_string(hostname));
    json_object_object_add(jobj,"machine_ip", json_object_new_string(ip));
    //TODO get device use_status and hardware status
    json_object_object_add(jobj, KEYNAME_USE_STATUS, json_object_new_string(g_use_status));
    json_object_object_add(jobj,"device_status", json_object_new_string(g_device_status));
        
    debug(LOG_DEBUG, "json='%s', len=%lu\n", json_object_to_json_string(jobj), strlen(json_object_to_json_string(jobj)));
    debug(LOG_DEBUG, "url=%s\n", url);

    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(jobj));
    /* set timeout */
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, (long)155);
    
    /* set url to fetch */
    curl_easy_setopt(ch, CURLOPT_URL, url);

    /* set calback function */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) cf);

    /* set default user agent */
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");

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
    if (jobj != NULL) {
        debug(LOG_DEBUG, "Free JSON");
        json_object_put(jobj);
    }

    if (rcode != CURLE_OK || cf->size < 1) {
            /* log error */
            debug(LOG_ERR, "%s Failed to fetch url (%s) '%s'", __func__, 
                url, curl_easy_strerror(rcode));
            /* return error */
            return 2;
     }

    /* check payload */
    if (cf->payload != NULL) {
        /* print result */
        debug(LOG_DEBUG, "CURL Returned='%s' len=%lu\n", cf->payload, strlen(cf->payload));
        /* parse return */
        jobj = json_tokener_parse(cf->payload); //json_tokener_parse_verbose(cf->payload, &jerr);
        /* free payload */
        free(cf->payload);
    } else {
        /* error */
        debug(LOG_ERR, "Failed to populate payload");
        /* free payload */
        free(cf->payload);
        /* return */
        return 3;
    }

    /* check error */
    if (jobj == NULL) {
        /* error */
        debug(LOG_ERR, "ERROR: Failed to parse json string");
        /* free json object */
        json_object_put(jobj);
        /* return */
        return 4;
    }

    /* debugging */
    debug(LOG_DEBUG, "%s Parsed JSON: %s\n", __func__, json_object_to_json_string(jobj));

    // key checking
    json_object_object_get_ex(jobj, "sign", &retobj);
    recv_item = json_object_get_string(retobj);
    if (NULL == recv_item) {
        debug(LOG_ERR, "%s no new signkey\n", __func__);
        return 5;
    }

    if (0 != strcmp(recv_item, tmpkey)) {
         debug(LOG_ERR, "recv_sign %s != %s!", recv_item, tmpkey);
         return -1;       
    }
    
    // parse config data from the JSON string
    json_object_object_get_ex(jobj, "newsign", &retobj);
    recv_item = json_object_get_string(retobj);
    if (NULL == recv_item) {
        debug(LOG_ERR, "%s no new newkey\n", __func__);
        return 5;
    }    
    memcpy(signkey, recv_item, sizeof(signkey) - 1);
    debug(LOG_DEBUG, "newsign=%s oldsignkey=%s\n", recv_item, tmpkey);

    json_object_object_get_ex(jobj, "use_status", &retobj);
    recv_item = json_object_get_string(retobj);
    if (NULL == recv_item) {
        debug(LOG_ERR, "%s no use_status\n", __func__);
        return 5;
    }
    memcpy(g_use_status, recv_item, sizeof(g_use_status) - 1);
    debug(LOG_DEBUG, "g_use_status=%s\n", recv_item);

    json_object_object_get_ex(jobj, KEYNAME_CHARGING_TYPE, &retobj);
    recv_item = json_object_get_string(retobj);
    if (NULL == recv_item) {
        debug(LOG_ERR, "%s no charging_type\n", __func__);
        return 5;
    }
    memcpy(g_charging_type, recv_item, sizeof(g_charging_type) - 1);
    set_data(KEYNAME_CHARGING_TYPE, g_charging_type);
    debug(LOG_DEBUG, "charging_type=%s\n", recv_item);

    json_object_object_get_ex(jobj, "charging_time_s", &retobj);
    recv_item = json_object_get_string(retobj);
    if (NULL == recv_item) {
        debug(LOG_ERR, "%s no charging_time_s\n", __func__);
        return 5;
    }
    memcpy(g_charging_time_s, recv_item, sizeof(g_charging_time_s) - 1);
    debug(LOG_DEBUG, "charging_time_s='%s'\n", recv_item);
    set_data(KEYNAME_CHARGING_TIME_S, g_charging_time_s);

    json_object_object_get_ex(jobj, "charging_time_e", &retobj);
    recv_item = json_object_get_string(retobj);
    if (NULL == recv_item) {
        debug(LOG_ERR, "%s no charging_time_e\n", __func__);
        return 5;
    }
    memcpy(g_charging_time_e, recv_item, sizeof(g_charging_time_e) - 1);
    debug(LOG_DEBUG, "charging_time_e='%s'\n", recv_item);
    set_data(KEYNAME_CHARGING_TIME_E, g_charging_time_e);

    json_object_object_get_ex(jobj, "pour_timeout", &retobj);
    recv_item = json_object_get_string(retobj);
    if (NULL == recv_item) {
        debug(LOG_ERR, "%s no pour_timeout\n", __func__);
        return 5;
    }
    memcpy(g_pour_timeout, recv_item, sizeof(g_pour_timeout) - 1);
    debug(LOG_DEBUG, "g_pour_timeout=%s\n", recv_item);
    set_data(KEYNAME_POUR_TIMEOUT, g_pour_timeout);
    
    if (jobj != NULL) {
        debug(LOG_DEBUG, "%s Free JSON\n", __func__);
        json_object_put(jobj);
    }

    return 0;

}

// thread: send IP to server and update local sign key
static void *postthreadfunc(void *arg)
{
    char *p = NULL;
    unsigned int count = 0;
    
    debug(LOG_DEBUG, "+%s tid=%lu", __func__, syscall(SYS_gettid));

    debug(LOG_DEBUG, "+%s", __func__);
    while (1) {
        if (check_ip()) { // IP changed, send the IP using orgsign
            memcpy(signkey, master_sign, sizeof(signkey));
            postip(config.serverurl);     
        } else { // The same IP report heartbeat very 600 seconds
            if ((count * atoi(g_ipcheck_time)) >= 600) {
                count = 0;
                postip(config.serverurl);
            }
        }
        count++;
        debug(LOG_DEBUG, "%s sleep %d", __func__, atoi(g_ipcheck_time));        
        sleep(atoi(g_ipcheck_time));
    }

    debug(LOG_DEBUG, "-%s", __func__);    
    return NULL;
}

static void
notify_connection_cb(void *cls, struct MHD_Connection *connection, void **socket_data,
    enum MHD_ConnectionNotificationCode code)
{
    const union MHD_ConnectionInfo * conninfo;

    conninfo = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_DAEMON);

    debug(LOG_DEBUG, "%s code=%d connection=%p daemon=%p tid=%lu", 
        __func__, code, connection, conninfo->daemon, syscall(SYS_gettid));
    
    //MHD_get_daemon_info(conninfo->daemon, MHD_DAEMON_INFO_CURRENT_CONNECTIONS);
}

// main thread
static int httpserver()
{
    struct MHD_Daemon *d;
    pthread_t  postthread;
    int ret;
  
    debug(LOG_NOTICE, "%s on port %d", __func__, config.port);

    // only one connection is allowed! 
    d = MHD_start_daemon(// MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | MHD_USE_POLL,
			//MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG,
			MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG ,
                        config.port,
                        NULL, NULL, &http_callback, PAGE,
			MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 5,
	        //MHD_OPTION_THREAD_POOL_SIZE, (unsigned int) 1,
	        MHD_OPTION_CONNECTION_LIMIT, (unsigned int)1,
	        MHD_OPTION_NOTIFY_CONNECTION, notify_connection_cb, NULL,
			MHD_OPTION_END);
  if (d == NULL) {
        debug(LOG_ERR, "start fail!");
        return 1;
   }

    debug(LOG_DEBUG, "%s d=%p", __func__, d);


  ret = pthread_create(&postthread, 0 , postthreadfunc, NULL);
  if ( 0 != ret) {
      debug(LOG_ERR, "therea create fail %d", ret);    
      return -1;
  }
  
  pthread_detach(postthread);

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

int main(int argc, char  **argv)
{
    int ret = 0;
    char value[32] = "";

    config_init();
    config_dump();
    parse_commandline(argc, argv);
    config_dump();

    snprintf(g_gap_no, sizeof(g_gap_no), "%s", "A0001AGAP001");

    snprintf(g_server_url, sizeof(g_server_url), "%s", config.serverurl);
    //get_data(key, value);
    set_data(KEYNAME_SERVER_URL, g_server_url);

    snprintf(g_ipcheck_time, sizeof(g_ipcheck_time), "%d", config.interval);
    set_data(KEYNAME_REPORT_TIME, g_ipcheck_time);

    // TODO hardware checking
    snprintf(g_device_status, sizeof(g_device_status), "%s", HARDWARE_DEVICE_NORMAL);
    snprintf(g_result, sizeof(g_result), "%s", RESULT_NORMAL);

    // TODO query settings from DB
    ret = get_data(KEYNAME_CHARGING_TYPE, value);
    if (ret || (0 == strlen(value))) {
        snprintf(value, sizeof(value), "%s", CHARGING_TYPE_COUNT);        
        set_data(KEYNAME_CHARGING_TYPE, value);
    }
    snprintf(g_charging_type, sizeof(g_charging_type), "%s", value);

    ret = get_data(KEYNAME_CHARGING_TIME_S, value);
    snprintf(g_charging_time_s, sizeof(g_charging_time_s), "%s", value);

    ret = get_data(KEYNAME_CHARGING_TIME_E, value);
    snprintf(g_charging_time_e, sizeof(g_charging_time_e), "%s", value);

    ret = get_data(KEYNAME_USE_STATUS, value);
    if (ret || (0 == strlen(value))) {
        snprintf(value, sizeof(value), "%s", USE_STATUS_NORMAL);
        set_data(KEYNAME_USE_STATUS, value);
    }
    snprintf(g_use_status, sizeof(g_use_status), "%s", value);

    ret = get_data(KEYNAME_POUR_TIMEOUT, value);
    if (ret || (0 == strlen(value))) {
        snprintf(value, sizeof(value), "%s", DEFAULT_POUR_TIMEOUT);
        set_data(KEYNAME_POUR_TIMEOUT, value);
    }
    snprintf(g_pour_timeout, sizeof(g_pour_timeout), "%s", value);
    
    printf("%s\n", __func__);
    printf("%s tid=%lu\n", __func__, syscall(SYS_gettid));

    pthread_mutex_init(&processing_mutex, NULL);

    if (sem_init(&stopsem, 0, 0) == -1) {
        debug(LOG_ERR, "sem_init");
    }
    
    init_signals();

    debug(LOG_NOTICE, "Client Built on %s-%s", __DATE__, __TIME__);
    debug(LOG_DEBUG, "Client Built on %s-%s", __DATE__, __TIME__);

    //debug(LOG_DEBUG, "start process for httpserver daemon=%d", config.daemon);
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
    pthread_mutex_destroy(&processing_mutex);
    debug(LOG_NOTICE, "main return 0...");
	return(0); /* never reached */
}

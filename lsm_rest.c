/*
 * Copyright (C) 2011-2013 Red Hat, Inc.
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 *
 * Author: Gris Ge <fge <at> redhat.com>
 * gcc lsm_rest.c -lmicrohttpd -ljson-c -luriparser -o lsm_restd
 * LSM_UDS_PATH=/tmp/lsm/ipc ./lsm_restd
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <microhttpd.h>
#include <json-c/json.h>
#include <uriparser/Uri.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <stdlib.h>

#define PORT 8888
#define TMO 60000
#define LSM_SOCK_BUFF_LEN 250 // No idea why 4096 fail.
#define LSM_DEFAULT_ID 100
#define JSON_MIME "application/json"
#define LSM_HEADER_LEN 10
#define LSM_API_VER_LEN 4

int connect_socket(const char *uri_str, const char *plugin_dir,
	int *error_no)
{
	UriParserStateA uri_state;
	UriUriA uri_obj;
	uri_state.uri = &uri_obj;
	int socket_fd = -1;
	if (uriParseUriA(&uri_state, uri_str) != URI_SUCCESS) {
		/* Failure */
		uriFreeUriMembersA(&uri_obj);
		*error_no = errno;
		return socket_fd;
	}
	ssize_t uri_scheme_len = uri_obj.scheme.afterLast - uri_obj.scheme.first;
	char *uri_scheme = malloc(uri_scheme_len + 1);
	memset(uri_scheme, 0, uri_scheme_len + 1);
	memcpy(uri_scheme, uri_obj.scheme.first, uri_scheme_len);
	char *plugin_file = NULL;
	if (asprintf(&plugin_file, "%s/%s", plugin_dir, uri_scheme) == -1){
		*error_no = ENOMEM;
		return socket_fd;
	}
	uriFreeUriMembersA(&uri_obj);
	printf("URI scheme found: %s\n", uri_scheme);
	printf("Using socket file: %s\n", plugin_file);

	socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (socket_fd != -1){
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		if (strlen(plugin_file) > (sizeof(addr.sun_path) - 1)){
			socket_fd = -1;
			fprintf(stderr, "Plugin file path too long: %s, "
				"max is %d", plugin_file,
				sizeof(addr.sun_path) - 1);
		}
		strcpy(addr.sun_path, plugin_file);
		if (connect(socket_fd, (struct sockaddr *) &addr,
			sizeof(addr)) != 0){
			*error_no = errno;
			socket_fd = -1;
		}
	}else{
		*error_no = errno;
	}
	printf("Socket connected: %d\n", socket_fd);
	return socket_fd;
}

int send_msg(int socket_fd, const char *msg, int *error_no)
{
	int rc = -1;
	ssize_t len = strlen(msg);
	char * msg_with_header = malloc(strlen(msg) + LSM_HEADER_LEN + 1);
	sprintf(msg_with_header, "%0*d%s", LSM_HEADER_LEN, len, msg);
	ssize_t written = 0;
	msg = msg_with_header;
	len = strlen(msg_with_header);
	printf("Sending json message to socket %d\n%s\n", socket_fd,
		msg_with_header);
	while (written < len) {
		ssize_t wrote = send(socket_fd, msg + written,
			(strlen(msg) - written),
			MSG_NOSIGNAL);
		if (wrote != -1){
			written += wrote;
		}else{
			*error_no = errno;
			break;
		}
	}
	if ((written == strlen(msg)) && *error_no == 0){
		rc = 0;
	}
	printf("Json message sent\n");
	return rc;
}

const char *_recv_msg(int socket_fd, size_t count, int *error_no)
{
	char buff[LSM_SOCK_BUFF_LEN];
	size_t amount_read = 0;
	*error_no = 0;
	char *msg = malloc(count + 1);
	memset(msg, 0, count + 1);
	while (amount_read < count) {
		ssize_t rd = (ssize_t)recv(socket_fd, buff,
			MIN(sizeof(buff), count - amount_read), MSG_WAITALL);
		if (rd > 0) {
			memcpy(msg + amount_read, buff, rd);
			amount_read += rd;
		}
		else if(errno == EAGAIN){
			printf("retry\n");
			errno = 0;
			continue; // TODO: don't know why recv() don't block.
		}
		else {
			*error_no = errno;
			break;
		}
	}
	if (*error_no == 0){
		msg[count] = '\0';
		return msg;
	}
	else{
		fprintf(stderr, "recv() got error_no, : %d\n", *error_no);
		return NULL;
	}
}

const char *recv_msg(int socket_fd, int *error_no)
{
	*error_no = 0;
	const char *msg_len_str = _recv_msg(socket_fd, LSM_HEADER_LEN,
		error_no);
	printf ("msg_len_str: %s\n", msg_len_str);
	if (msg_len_str == NULL){
		fprintf(stderr, "Failed to read the JSON length "
			"with error_no%d\n", *error_no);
		return NULL;
	}
	errno = 0;
	size_t msg_len = (size_t)strtoul(msg_len_str, NULL, 10);
	if ((errno == ERANGE && (msg_len == LONG_MAX || msg_len == LONG_MIN))
		|| (errno != 0 && msg_len == 0))
	{
		perror("strtol");
		return NULL;
	}
	if (msg_len == 0){
		fprintf(stderr, "No data needed to retrieve\n");
		return NULL;
	}
	printf("Receiving data with length %d\n", msg_len);
	const char *msg = _recv_msg(socket_fd, msg_len, error_no);
	if (msg == NULL){
		fprintf(stderr, "Failed to retrieve data from socket "
			"with error_no %d\n", *error_no);
		return NULL;
	}
	printf("Got json data:\n%s\n", msg);
	return msg;
}

const char *rpc(int socket_fd, const char *method, json_object *js_params,
	int *error_no)
{
	*error_no = 0;
	json_object * jobj = json_object_new_object();
	json_object_object_add(jobj,"method", json_object_new_string(method));
	json_object_object_add(jobj,"params", js_params);
	json_object_object_add(jobj,"id", json_object_new_int(LSM_DEFAULT_ID));
	const char *json_string = json_object_to_json_string(jobj);
	printf ("The json object created:\n%s\n", json_string); // code_debug
	*error_no = 0;
	int rc = send_msg(socket_fd, json_string, error_no);
	if (rc != 0){
		fprintf(stderr, "Got error when sending message to socket, "
			"rc=%d, error_no=%d\n", rc, *error_no);
		return NULL;
	}
	const char *recv_json_string = NULL;
	recv_json_string = recv_msg(socket_fd, error_no);
	printf("recv_msg() got length: %d\n", (strlen(recv_json_string)));
	if (*error_no != 0){
		printf("Got error when receiving message to socket,"
			"error_no=%d\n", *error_no);
		return NULL;
	}
	if (recv_json_string == NULL){
		printf("No data retrieved\n");
		return NULL;
	}
	json_object *recv_json = json_tokener_parse(recv_json_string);
	return json_object_get_string(
		json_object_object_get(recv_json, "result"));
}

int plugin_startup(int socket_fd, const char *uri, const char *pass, int tmo)
{
	printf("Starting the plugin\n");
	int error_no = 0;
	json_object *jobj_params = json_object_new_object();
	json_object_object_add(jobj_params,"uri", json_object_new_string(uri));
	if (pass != NULL){
		json_object_object_add(jobj_params, "password",
			json_object_new_string(pass));
	}else{
		json_object_object_add(jobj_params, "password",
			json_type_null);
	}
	json_object_object_add(jobj_params,"timeout", json_object_new_int(tmo));
	rpc(socket_fd, "startup", jobj_params, &error_no);
	return error_no;
}

int plugin_shutdown(int socket_fd)
{
	printf("Shutting down the plugin\n");
	int error_no = 0;
	json_object *jobj_params = json_object_new_object();
	json_object_object_add(jobj_params,"flags", json_object_new_int(0));
	rpc(socket_fd, "shutdown", jobj_params, &error_no);
	return error_no;
}

const char *v01_systems(int socket_fd, int *error_no)
{
	*error_no = 0;
	const char *method = "systems";
	json_object *js_params = json_object_new_object();
	json_object_object_add(js_params, "flags", json_object_new_int(0));
	return rpc(socket_fd, method, js_params, error_no);
}
const char *v01_volumes(int socket_fd, int *error_no)
{
	const char *method = "volumes";
	*error_no = 0;
	json_object *js_params = json_object_new_object();
	json_object_object_add(js_params, "flags", json_object_new_int(0));
	return rpc(socket_fd, method, js_params, error_no);
}
const char *v01_pools(int socket_fd, int *error_no)
{
	*error_no = 0;
	const char *method = "pools";
	json_object *js_params = json_object_new_object();
	json_object_object_add(js_params, "flags", json_object_new_int(0));
	return rpc(socket_fd, method, js_params, error_no);
}

const char *lsm_api_0_1(struct MHD_Connection *connection,
	const char * uri, const char * pass,
	const char *url, const char *method,
	const char *upload_data)
{
	const char *json_str = NULL;
	const char *plugin_dir = getenv("LSM_UDS_PATH");
	if (plugin_dir == NULL){
		fprintf(stderr, "Please define LSM_UDS_PATH\n");
		exit(1);
	}
	int error_no = 0;
	int socket_fd = connect_socket(uri, plugin_dir, &error_no);
	if (socket_fd == -1){
		fprintf(stderr, "Failed to connecting to the socket for URI "
			"%s with error_no %d\n", uri, error_no);
		return NULL;
	}
	error_no = plugin_startup(socket_fd, uri, pass, TMO);
	if (error_no != 0){
		fprintf(stderr, "Failed to startup plugin, "
			"error_no %d", error_no);
		plugin_shutdown(socket_fd);
		shutdown(socket_fd, 0);
		return NULL;
	}
	error_no = 0;
	printf("URL: %s, len: %d\n", url, strlen(url));
	const char *json_msg = NULL;
	if (0 == strcmp(url, "systems")){
		json_msg = v01_systems(socket_fd, &error_no);
	}else if ( 0 == strcmp(url, "pools")){
		json_msg = v01_pools(socket_fd, &error_no);
	}else if ( 0 == strcmp(url, "volumes")){
		json_msg = v01_volumes(socket_fd, &error_no);
	}else{
		fprintf(stderr, "Not supported: %s\n", url);
	}
	if (error_no != 0){
		fprintf(stderr, "Failed to call method %s, error_no: %d\n",
			url, error_no);
	}
	error_no = plugin_shutdown(socket_fd);
	if (error_no != 0){
		fprintf(stderr, "Failed to shutdown plugin, "
			"error_no %d", error_no);
	}
	shutdown(socket_fd, 0);
	return json_msg;
}

int answer_to_connection(void *cls, struct MHD_Connection *connection,
	const char *url,
	const char *method, const char *version,
	const char *upload_data,
	size_t *upload_data_size, void **con_cls)
{
	printf ("New %s request, URL: [%s]\n", method, url); // code_debug
	printf ("version: [%s] upload_data: [%s]\n", version, upload_data); // code_debug

	struct MHD_Response *response;

	if (0 != strcmp (method, "GET")){
		return MHD_NO;
	}

	if (strlen(url) == 1){
		return MHD_NO;
	}


#if 0
    service_resource::render_POST()
    POST Request [user:"" pass:""] path:"/service"
        Headers [Host:"192.168.0.51:8080" Accept:"application/json" Origin:"chrome-extension://ecjfcmddigpdlehfhdnnnhfgihkmejin" Connection:"keep-alive" User-Agent:"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" Content-Type:"application/json" Content-Length:"67" Accept-Encoding:"gzip, deflate" Accept-Language:"en-US,en;q=0.8" ]
        Version [ HTTP/1.1 ] Requestor [ 192.168.0.70 ] Port [ 3034 ]
    request content:{"command":"get_detail","sign":"2380BEC2BFD727A4B6845133519F3AD6",}
    Response [response_code:200]
        Headers [Content-Type:"text/plain" ]
#endif

#if 0
MHD_set_connection_value kind=8 key=[aa] value=[bb]
MHD_set_connection_value kind=1 key=[Host] value=[192.168.0.51:8888]
MHD_set_connection_value kind=1 key=[Connection] value=[keep-alive]
MHD_set_connection_value kind=1 key=[Content-Length] value=[2]
MHD_set_connection_value kind=1 key=[Accept] value=[application/json]
MHD_set_connection_value kind=1 key=[Origin] value=[chrome-extension://ecjfcmddigpdlehfhdnnnhfgihkmejin]
MHD_set_connection_value kind=1 key=[User-Agent] value=[Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36]
MHD_set_connection_value kind=1 key=[Content-Type] value=[application/json]
MHD_set_connection_value kind=1 key=[Accept-Encoding] value=[gzip, deflate]
MHD_set_connection_value kind=1 key=[Accept-Language] value=[en-US,en;q=0.8]

#endif

	const char *uri = MHD_lookup_connection_value (connection,
		MHD_GET_ARGUMENT_KIND, "uri");

	const char *pass= MHD_lookup_connection_value (connection,
		MHD_GET_ARGUMENT_KIND, "pass");

    printf("uri=%s pass=%s\n", uri, pass);

	int ret;
	char api_version[LSM_API_VER_LEN + 1];
	memcpy(api_version, url + 1 , LSM_API_VER_LEN);
	// url + 1 is used to get rid of leading '/'
	api_version[LSM_API_VER_LEN] = '\0';
	const char *json_str = NULL;
	size_t url_no_api_ver_len = strlen(url) - strlen(api_version) - 1 - 1;
	// -1 -1 means remove two leading /
	// example: /v0.1/systems  --change to--> systems
	char *url_no_api_ver = malloc(url_no_api_ver_len + 1);
	memset(url_no_api_ver, 0, url_no_api_ver_len + 1);
	memcpy(url_no_api_ver, (url + strlen(api_version) + 1 + 1),
		url_no_api_ver_len);
	if ( 0 == strcmp(api_version, "v0.1" )){
		printf("v0.1 API request found\n"); // code_debug
		json_str = lsm_api_0_1(connection, uri, pass, url_no_api_ver,
			method, upload_data);
		if(json_str == NULL){
			return MHD_NO;
		}
	}else{
		return MHD_NO;
	}
	printf("Returning JSON str via http: \n%s\n", json_str);
	response = MHD_create_response_from_buffer(
		strlen(json_str),
		(void*) json_str, MHD_RESPMEM_PERSISTENT);

	MHD_add_response_header(response, "Content-Type", JSON_MIME);

	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	return ret;
}

int main (int argc, char *argv[])
{
	struct MHD_Daemon *daemon;
	daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
		&answer_to_connection, NULL, MHD_OPTION_END);
	if (NULL == daemon) return 1;
    printf("Listen on %d\n", PORT);
	getchar();
	MHD_stop_daemon(daemon);
	return 0;
}

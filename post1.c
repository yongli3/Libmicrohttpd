#include <string>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <cstring>
#include <microhttpd.h>
 
using namespace std;
 
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
 
int main (int argc, char** argv)
{
 
        MHD_Daemon* daemon = MHD_start_daemon(
                                        MHD_USE_SELECT_INTERNALLY, 8001, NULL, NULL,
                                        &handle_request, NULL, MHD_OPTION_END);
 
        if(!daemon) {
                cerr << "Failed to start HTTP server " << endl;
                return 1;
        }
 
        // Handle requests until we're asked to stop
        for(;;) {
                MHD_run (daemon);
                usleep(1000*1000);
        }
        return 0;
}



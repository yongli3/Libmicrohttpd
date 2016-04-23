/*
     This file is part of libmicrohttpd
     Copyright (C) 2007, 2009, 2011, 2015, 2016 Christian Grothoff

     libmicrohttpd is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     libmicrohttpd is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with libmicrohttpd; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file test_concurrent_stop.c
 * @brief test stopping server while concurrent GETs are ongoing
 * @author Christian Grothoff
 */
#include "MHD_config.h"
#include "platform.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "gauger.h"

#ifdef CPU_COUNT
#undef CPU_COUNT
#endif
#define CPU_COUNT 40


/**
 * How many rounds of operations do we do for each
 * test (total number of requests will be ROUNDS * PAR).
 */
#define ROUNDS 50000

/**
 * How many requests do we do in parallel?
 */
#define PAR CPU_COUNT

/**
 * Do we use HTTP 1.1?
 */
static int oneone;

/**
 * Response to return (re-used).
 */
static struct MHD_Response *response;


static size_t
copyBuffer (void *ptr,
	    size_t size, size_t nmemb,
	    void *ctx)
{
  return size * nmemb;
}


static int
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data,
          size_t *upload_data_size,
          void **unused)
{
  static int ptr;
  const char *me = cls;
  int ret;

  if (0 != strcmp (me, method))
    return MHD_NO;              /* unexpected method */
  if (&ptr != *unused)
    {
      *unused = &ptr;
      return MHD_YES;
    }
  *unused = NULL;
  ret = MHD_queue_response (connection,
                            MHD_HTTP_OK,
                            response);
  if (ret == MHD_NO)
    abort ();
  return ret;
}


static void *
thread_gets (void *param)
{
  CURL *c;
  CURLcode errornum;
  unsigned int i;
  char * const url = (char*) param;

  for (i=0;i<ROUNDS;i++)
    {
      c = curl_easy_init ();
      curl_easy_setopt (c, CURLOPT_URL, url);
      curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
      curl_easy_setopt (c, CURLOPT_WRITEDATA, NULL);
      curl_easy_setopt (c, CURLOPT_FAILONERROR, 1);
      curl_easy_setopt (c, CURLOPT_TIMEOUT, 150L);
      if (oneone)
        curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
      else
        curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
      curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 150L);
      /* NOTE: use of CONNECTTIMEOUT without also
         setting NOSIGNAL results in really weird
         crashes on my system! */
      curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1);
      if (CURLE_OK != (errornum = curl_easy_perform (c)))
        {
          curl_easy_cleanup (c);
          return NULL;
        }
      curl_easy_cleanup (c);
    }

  return NULL;
}

#ifndef SIGKILL
#define SIGKILL SIGTERM
#endif /* ! SIGKILL */

static void *
do_gets (void * param)
{
  unsigned int j;
  pthread_t par[PAR];
  char url[64];
  int port = (int)(intptr_t)param;

  sprintf(url, "http://127.0.0.1:%d/hello_world", port);

  for (j=0;j<PAR;j++)
    {
      if (0 != pthread_create(&par[j], NULL, &thread_gets, (void*)url))
        {
          for (j--; j >= 0; j--)
            pthread_join(par[j], NULL);

          fprintf(stderr, "pthread_create failed.\n");
          _exit(99);
        }
    }
  for (j=0;j<PAR;j++)
    {
      pthread_kill(par[j], SIGKILL);
      pthread_join(par[j], NULL);
    }
  return NULL;
}


pthread_t start_gets(int port)
{
  pthread_t tid;
  if (0 != pthread_create(&tid, NULL, &do_gets, (void*)(intptr_t)port))
    {
      fprintf(stderr, "pthread_create failed.\n");
      _exit(99);
    }
  return tid;
}


static int
testMultithreadedGet (int port,
                      int poll_flag)
{
  struct MHD_Daemon *d;
  pthread_t p;

  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG  | poll_flag,
                        port,
                        NULL, NULL,
                        &ahc_echo, "GET",
                        MHD_OPTION_END);
  if (d == NULL)
    return 16;
  p = start_gets (port);
  sleep (1);
  MHD_stop_daemon (d);
  pthread_join (p, NULL);
  return 0;
}


static int
testMultithreadedPoolGet (int port,
                          int poll_flag)
{
  struct MHD_Daemon *d;
  pthread_t p;

  d = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | poll_flag,
                        port,
                        NULL, NULL,
                        &ahc_echo, "GET",
                        MHD_OPTION_THREAD_POOL_SIZE, CPU_COUNT,
                        MHD_OPTION_END);
  if (d == NULL)
    return 16;
  p = start_gets (port);
  sleep (1);
  MHD_stop_daemon (d);
  pthread_join (p, NULL);
  return 0;
}


int
main (int argc, char *const *argv)
{
  unsigned int errorCount = 0;
  int port = 1081;

  oneone = (NULL != strrchr (argv[0], (int) '/')) ?
    (NULL != strstr (strrchr (argv[0], (int) '/'), "11")) : 0;
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    return 2;
  response = MHD_create_response_from_buffer (strlen ("/hello_world"),
					      "/hello_world",
					      MHD_RESPMEM_MUST_COPY);
  errorCount += testMultithreadedGet (port++, 0);
  errorCount += testMultithreadedPoolGet (port++, 0);
  MHD_destroy_response (response);
  if (errorCount != 0)
    fprintf (stderr, "Error (code: %u)\n", errorCount);
  curl_global_cleanup ();
  return errorCount != 0;       /* 0 == pass */
}

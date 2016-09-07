#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

int main()
{
    /* Warning: error checking removed to keep the example small */
    pthread_attr_t attr;
    size_t stacksize;
    struct rlimit rlim;

    pthread_attr_init(&attr);
    pthread_attr_getstacksize(&attr, &stacksize);
    getrlimit(RLIMIT_STACK, &rlim);
    /* Don't know the exact type of rlim_t, but surely it will
       fit into a size_t variable. */
    printf("%zd\n", (size_t) rlim.rlim_cur);
    printf("%zd\n", stacksize);
    pthread_attr_destroy(&attr);

    return 0;
}


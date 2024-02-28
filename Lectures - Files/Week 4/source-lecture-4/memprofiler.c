#define _GNU_SOURCE  /* For RTLD_NEXT.  */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define die(...) \
    do { \
        fprintf(stderr, "min_strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

void debug_print(char *mem) {
    int i = 0;
    do {
        putc((char)mem[i], stderr);
    } while (mem[i++] != '\0');

    putc('\n', stderr);
}

long stats_total_malloc = 0;
long stats_total_free = 0;

typedef void *(*real_malloc_t)(size_t);
static real_malloc_t real_malloc = NULL;

void * malloc(size_t size) {

    if (!real_malloc) {
        real_malloc = (real_malloc_t) dlsym(RTLD_NEXT, "malloc");
        if (!real_malloc) {
                die("real malloc problem: %s", dlerror());
        }
    }

    void *p = (void *)real_malloc(size);
    stats_total_malloc++;

    return p;
}


typedef void *(*real_free_t)(void *);
static real_free_t real_free = NULL;

void free(void *ptr) {

    if (!real_free) {
        real_free = (real_free_t)dlsym(RTLD_NEXT, "free");
        if (!real_free) 
            die("real free problem: %s", dlerror());
    }

    real_free(ptr);
    stats_total_free++;

    return;
}

__attribute__((destructor)) static void stats(void) {
    printf("malloc() calls recorded: %ld\n", stats_total_malloc);
    printf("free() calls recorded: %ld\n", stats_total_free);
}



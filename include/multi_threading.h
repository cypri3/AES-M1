#ifndef MULTI_THREADING_H
#define MULTI_THREADING_H
#include "utils.h"

// Definition of the generic function type that can be passed as a parameter
typedef void *(*thread_function)(void *);

// Structure for threads arguments
typedef struct
{
    Block *block;
    unsigned char *expanded_key;
    int *Nr;
} ThreadArgs;

void run_function_in_thread(thread_function func, void *args);
void *process_blocks_ECB(void *args);

#endif /* MULTI_THREADING_H */
#include <pthread.h>
#include <stdio.h>
#include "utils.h"
#include "AES_fun.h"
#include "ECB.h"
#include "multi_threading.h"

// Définir la barrière
pthread_barrier_t barrier;

/**
 * Function to execute a given function in a separate thread.
 *
 * @param func A pointer to the function to be executed.
 * @param args A pointer to the arguments to be passed to the function.
 */
void run_function_in_thread(thread_function func, void *args)
{
    pthread_t thread;

    // Create a thread to execute the given function
    if (pthread_create(&thread, NULL, func, args))
    {
        perror("pthread_create");
        return;
    }

    // Wait for the thread to finish
    // pthread_join(thread, NULL);
}

/**
 * Function executed by the thread to process blocks with AESEncryptionECB.
 *
 * @param args The arguments needed to execute AESEncryptionECB.
 *             The arguments should be an array with three elements:
 *             - Block *blocks: Pointer to the blocks to be processed.
 *             - unsigned char *expanded_key: Pointer to the expanded key.
 *             - int *Nr: Pointer to the number of rounds.
 */
void *process_blocks_ECB(void *args)
{
    // Unpack the arguments
    void **arguments = (void **)args;
    Block *blocks = (Block *)arguments[0];
    unsigned char *expanded_key = (unsigned char *)arguments[1];
    int Nr = *((int *)arguments[2]);

    // Wait the barrier
    pthread_barrier_wait(&barrier);

    // Call AESEncryptionECB with the given arguments
    AESEncryptionECB(blocks, expanded_key, Nr);

    pthread_exit(NULL);
}

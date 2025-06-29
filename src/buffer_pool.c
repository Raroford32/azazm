/**
 * buffer_pool.c
 *
 * Implements a high-performance, thread-safe memory pool for GSSAPI tokens to avoid frequent malloc/free calls.
 * This design minimizes heap fragmentation and lock contention, supporting massive concurrency for RDP NLA brute-force.
 *
 * Rationale: Token buffers are reused to reduce allocation overhead and improve cache locality. Mutex ensures thread safety.
 *
 * Author: Auto-generated, reviewed for optimal performance and safety.
 * Date: June 29, 2025
 */

#include "rdp_nla_checker.h"
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>

// Global token pool instance
// Rationale: Single pool shared by all threads, protected by mutex for safety.
gssapi_token_pool_t g_token_pool;

/**
 * Initialize the GSSAPI token buffer pool.
 * Allocates all buffers and initializes the mutex.
 *
 * Returns: void. Exits on fatal allocation error.
 */
void gssapi_token_pool_init(void) {
    if (pthread_mutex_init(&g_token_pool.mutex, NULL) != 0) {
        fprintf(stderr, "[FATAL] Failed to initialize token pool mutex\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < GSSAPI_TOKEN_POOL_SIZE; i++) {
        g_token_pool.buffers[i] = malloc(GSSAPI_TOKEN_BUFFER_SIZE);
        if (!g_token_pool.buffers[i]) {
            fprintf(stderr, "[FATAL] Failed to allocate token buffer %d\n", i);
            exit(EXIT_FAILURE);
        }
        g_token_pool.in_use[i] = false;
    }
}

/**
 * Cleanup the GSSAPI token buffer pool.
 * Frees all buffers and destroys the mutex.
 */
void gssapi_token_pool_cleanup(void) {
    for (int i = 0; i < GSSAPI_TOKEN_POOL_SIZE; i++) {
        free(g_token_pool.buffers[i]);
        g_token_pool.buffers[i] = NULL;
        g_token_pool.in_use[i] = false;
    }
    pthread_mutex_destroy(&g_token_pool.mutex);
}

/**
 * Acquire a token buffer from the pool.
 * Returns: pointer to buffer, or NULL if pool exhausted.
 * Thread-safe.
 */
uint8_t* gssapi_token_pool_get(void) {
    pthread_mutex_lock(&g_token_pool.mutex);
    for (int i = 0; i < GSSAPI_TOKEN_POOL_SIZE; i++) {
        if (!g_token_pool.in_use[i]) {
            g_token_pool.in_use[i] = true;
            pthread_mutex_unlock(&g_token_pool.mutex);
            return g_token_pool.buffers[i];
        }
    }
    pthread_mutex_unlock(&g_token_pool.mutex);
    return NULL; // Pool exhausted
}

/**
 * Release a token buffer back to the pool.
 * Thread-safe.
 */
void gssapi_token_pool_release(uint8_t* token) {
    pthread_mutex_lock(&g_token_pool.mutex);
    for (int i = 0; i < GSSAPI_TOKEN_POOL_SIZE; i++) {
        if (g_token_pool.buffers[i] == token) {
            g_token_pool.in_use[i] = false;
            break;
        }
    }
    pthread_mutex_unlock(&g_token_pool.mutex);
}

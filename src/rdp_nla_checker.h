/**
 * RDP NLA (CredSSP) Login Credentials Checker
 * 
 * High-performance RDP authentication checker with DPDK kernel-bypass
 * and epoll+OpenSSL fallback paths. Supports hardware crypto offload
 * via SmartNIC/DPU for maximum throughput (50,000+ HPS).
 * 
 * Author: Auto-generated based on build.md specifications
 * Date: June 29, 2025
 * License: MIT
 */

#ifndef RDP_NLA_CHECKER_H
#define RDP_NLA_CHECKER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <gssapi/gssapi.h>

/* Configuration constants */
#define MAX_CONNECTIONS         100000
#define MAX_THREADS             64
#define BUFFER_SIZE             8192
#define CREDSP_VERSION          2
#define RDP_DEFAULT_PORT        3389
#define TLS_HANDSHAKE_TIMEOUT   30
#define CREDSP_TIMEOUT          10

/* Connection states */
typedef enum {
    CONN_STATE_INIT = 0,
    CONN_STATE_TCP_CONNECTING,
    CONN_STATE_TLS_HANDSHAKING,
    CONN_STATE_CREDSP_AUTH,
    CONN_STATE_AUTHENTICATED,
    CONN_STATE_FAILED,
    CONN_STATE_COMPLETED
} connection_state_t;

/* Authentication results */
typedef enum {
    AUTH_RESULT_UNKNOWN = 0,
    AUTH_RESULT_SUCCESS,
    AUTH_RESULT_FAILED,
    AUTH_RESULT_TIMEOUT,
    AUTH_RESULT_ERROR
} auth_result_t;

/* CredSSP TSRequest structure */
typedef struct {
    uint32_t version;
    uint8_t *nego_tokens;
    uint32_t nego_tokens_len;
    uint8_t *auth_info;
    uint32_t auth_info_len;
    uint8_t *pub_key_auth;
    uint32_t pub_key_auth_len;
} ts_request_t;

/* CredSSP TSResponse structure */
typedef struct {
    uint32_t version;
    uint8_t *nego_tokens;
    uint32_t nego_tokens_len;
    uint8_t *auth_info;
    uint32_t auth_info_len;
    uint8_t *pub_key_auth;
    uint32_t pub_key_auth_len;
} ts_response_t;

/* Connection context */
typedef struct connection_ctx {
    int fd;
    void *ssl;
    struct sockaddr_in target;
    connection_state_t state;
    auth_result_t result;
    
    /* Timing */
    struct timeval start_time;
    struct timeval end_time;
    
    /* Buffers */
    uint8_t *recv_buffer;
    uint8_t *send_buffer;
    uint32_t recv_len;
    uint32_t send_len;
    
    /* CredSSP context */
    gss_ctx_id_t gss_context;
    ts_request_t *ts_request;
    ts_response_t *ts_response;
    
    /* Credentials */
    char *username;
    char *password;
    char *domain;
    
    /* Next connection in list */
    struct connection_ctx *next;
} connection_ctx_t;

/* Worker thread context */
typedef struct {
    int thread_id;
    int epoll_fd;
    void *ssl_ctx;
    pthread_t thread;
    
    /* Statistics */
    uint64_t connections_processed;
    uint64_t auth_success;
    uint64_t auth_failed;
    uint64_t timeouts;
    uint64_t errors;
    
    /* Connection pool */
    connection_ctx_t *active_connections;
    connection_ctx_t *free_connections;
    pthread_mutex_t pool_mutex;
} worker_ctx_t;

/* Main checker configuration */
typedef struct {
    /* General config */
    bool use_dpdk;
    int num_threads;
    int max_concurrent;
    int timeout_seconds;
    
    /* DPDK config */
    int dpdk_port_id;
    int dpdk_queue_id;
    bool hardware_crypto;
    
    /* OpenSSL config */
    char *ca_cert_path;
    char *client_cert_path;
    char *client_key_path;
    
    /* Target config */
    char **target_hosts;
    int *target_ports;
    int num_targets;
    
    /* Credentials */
    char **usernames;
    int num_usernames;
    char **passwords;
    int num_passwords;
    char **domains;
    int num_domains;
    
    /* Performance tuning */
    bool cpu_affinity;
    int *cpu_cores;
    bool hugepages;
    bool edge_triggered;
    
    /* Output */
    char *results_file;
    bool json_output;
    bool verbose;
} checker_config_t;

/* GSSAPI Token Buffer Pool */
#define GSSAPI_TOKEN_POOL_SIZE 1024
#define GSSAPI_TOKEN_BUFFER_SIZE 4096

typedef struct {
    uint8_t* buffers[GSSAPI_TOKEN_POOL_SIZE];
    bool in_use[GSSAPI_TOKEN_POOL_SIZE];
    pthread_mutex_t mutex;
} gssapi_token_pool_t;

/* Statistics structure */
typedef struct {
    uint64_t total_attempts;
    uint64_t successful_auths;
    uint64_t failed_auths;
    uint64_t timeouts;
    uint64_t errors;
    
    double start_time;
    double end_time;
    double duration;
    
    double avg_handshake_time;
    double avg_auth_time;
    double handshakes_per_second;
} checker_stats_t;

/* Function declarations */

/* Initialization */
int rdp_checker_init(checker_config_t *config);
void rdp_checker_cleanup(void);

/* DPDK path */
int dpdk_init(checker_config_t *config);
int dpdk_worker_loop(void *arg);
int dpdk_handle_connection(connection_ctx_t *conn);

/* epoll+OpenSSL path */
int epoll_init(checker_config_t *config);
int epoll_worker_loop(void *arg);
int epoll_handle_connection(connection_ctx_t *conn, worker_ctx_t *worker);

/* Connection management */
connection_ctx_t *connection_create(const char *host, int port, 
                                  const char *username, const char *password, 
                                  const char *domain);
void connection_destroy(connection_ctx_t *conn);
int connection_connect(connection_ctx_t *conn);
int connection_tls_handshake(connection_ctx_t *conn);

/* CredSSP implementation */
int credsp_init_context(connection_ctx_t *conn);
int credsp_create_ts_request(connection_ctx_t *conn);
int credsp_send_ts_request(connection_ctx_t *conn);
int credsp_recv_ts_response(connection_ctx_t *conn);
int credsp_parse_ts_response(connection_ctx_t *conn);
int credsp_authenticate(connection_ctx_t *conn);
void credsp_cleanup(connection_ctx_t *conn);

/* ASN.1 encoding/decoding */
int asn1_encode_ts_request(ts_request_t *req, uint8_t **out, uint32_t *out_len);
int asn1_decode_ts_response(uint8_t *data, uint32_t len, ts_response_t *resp);

/* GSSAPI/NTLM/Kerberos */
int gssapi_init_context(connection_ctx_t *conn);
int gssapi_create_nego_token(connection_ctx_t *conn, uint8_t **token, uint32_t *token_len);
int gssapi_process_response(connection_ctx_t *conn, uint8_t *token, uint32_t token_len);

/* Utilities */
int make_socket_nonblocking(int fd);
int set_socket_options(int fd);
double get_time_diff(struct timeval *start, struct timeval *end);
void print_connection_stats(connection_ctx_t *conn);
void print_worker_stats(worker_ctx_t *worker);
void print_global_stats(checker_stats_t *stats);

/* Buffer pool management */
void gssapi_token_pool_init(void);
void gssapi_token_pool_cleanup(void);
uint8_t* gssapi_token_pool_get(void);
void gssapi_token_pool_release(uint8_t* token);

/* Configuration */
int parse_config_file(const char *filename, checker_config_t *config);
int parse_targets_file(const char *filename, checker_config_t *config);
int parse_users_file(const char *filename, checker_config_t *config);
int parse_passwords_file(const char *filename, checker_config_t *config);
int parse_domains_file(const char *filename, checker_config_t *config);

/* Main entry points */
int run_dpdk_checker(checker_config_t *config);
int run_epoll_checker(checker_config_t *config);

#endif /* RDP_NLA_CHECKER_H */

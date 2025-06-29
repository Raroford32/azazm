/**
 * RDP NLA (CredSSP) Login Credentials Checker - Main Implementation
 * 
 * High-performance implementation with DPDK kernel-bypass and epoll+OpenSSL
 * fallback for maximum RDP authentication throughput.
 */

#include "rdp_nla_checker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include <netinet/tcp.h>
#include <sched.h>

/* OpenSSL includes */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>

/* GSSAPI includes */
#include <gssapi/gssapi.h>
#ifdef HAVE_GSSAPI_NTLM_H
#include <gssapi/gssapi_ntlm.h>
#endif

/* DPDK includes (conditional) */
#ifdef USE_DPDK
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>
#include <rte_ring.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#endif

/* Global state */
static checker_config_t *g_config = NULL;
static worker_ctx_t *g_workers = NULL;
static checker_stats_t g_stats = {0};
static volatile bool g_shutdown = false;

/* Forward declarations */
static void signal_handler(int sig);
static int setup_ssl_context(worker_ctx_t *worker);
static void cleanup_ssl_context(worker_ctx_t *worker);

/**
 * Initialize the RDP checker with given configuration
 */
int rdp_checker_init(checker_config_t *config) {
    if (!config) {
        fprintf(stderr, "Invalid configuration\n");
        return -1;
    }
    
    g_config = config;
    
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    /* Initialize GSSAPI */
    OM_uint32 minor_status;
    gss_init_sec_context(&minor_status, GSS_C_NO_CREDENTIAL, NULL, NULL,
                         GSS_C_NO_OID, 0, 0, GSS_C_NO_CHANNEL_BINDINGS,
                         GSS_C_NO_BUFFER, NULL, NULL, NULL, NULL);
    
    /* Allocate worker contexts */
    g_workers = calloc(config->num_threads, sizeof(worker_ctx_t));
    if (!g_workers) {
        perror("Failed to allocate worker contexts");
        return -1;
    }
    
    /* Initialize statistics */
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.start_time = time(NULL);
    
    printf("RDP NLA Checker initialized with %d threads\n", config->num_threads);
    printf("Mode: %s\n", config->use_dpdk ? "DPDK kernel-bypass" : "epoll+OpenSSL");
    printf("Targets: %d, Usernames: %d, Passwords: %d, Domains: %d\n", config->num_targets, config->num_usernames, config->num_passwords, config->num_domains);
    
    return 0;
}

/**
 * Cleanup resources
 */
void rdp_checker_cleanup(void) {
    g_shutdown = true;
    
    if (g_workers) {
        for (int i = 0; i < g_config->num_threads; i++) {
            worker_ctx_t *worker = &g_workers[i];
            
            /* Join worker thread */
            if (worker->thread) {
                pthread_join(worker->thread, NULL);
            }
            
            /* Cleanup SSL context */
            cleanup_ssl_context(worker);
            
            /* Close epoll fd */
            if (worker->epoll_fd > 0) {
                close(worker->epoll_fd);
            }
            
            /* Cleanup connection pools */
            connection_ctx_t *conn = worker->active_connections;
            while (conn) {
                connection_ctx_t *next = conn->next;
                connection_destroy(conn);
                conn = next;
            }
            
            conn = worker->free_connections;
            while (conn) {
                connection_ctx_t *next = conn->next;
                connection_destroy(conn);
                conn = next;
            }
            
            pthread_mutex_destroy(&worker->pool_mutex);
        }
        
        free(g_workers);
        g_workers = NULL;
    }
    
    /* Cleanup OpenSSL */
    EVP_cleanup();
    ERR_free_strings();
    
    printf("RDP NLA Checker cleanup completed\n");
}

/**
 * Signal handler for graceful shutdown
 */
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    g_shutdown = true;
}

/**
 * Setup SSL context for worker
 */
static int setup_ssl_context(worker_ctx_t *worker) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return -1;
    }
    
    /* Set SSL options for performance */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    
    /* Load certificates if provided */
    if (g_config->ca_cert_path) {
        if (SSL_CTX_load_verify_locations(ctx, g_config->ca_cert_path, NULL) != 1) {
            fprintf(stderr, "Failed to load CA certificate\n");
            SSL_CTX_free(ctx);
            return -1;
        }
    }
    
    if (g_config->client_cert_path && g_config->client_key_path) {
        if (SSL_CTX_use_certificate_file(ctx, g_config->client_cert_path, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "Failed to load client certificate\n");
            SSL_CTX_free(ctx);
            return -1;
        }
        
        if (SSL_CTX_use_PrivateKey_file(ctx, g_config->client_key_path, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "Failed to load client private key\n");
            SSL_CTX_free(ctx);
            return -1;
        }
    }
    
    worker->ssl_ctx = ctx;
    return 0;
}

/**
 * Cleanup SSL context
 */
static void cleanup_ssl_context(worker_ctx_t *worker) {
    if (worker->ssl_ctx) {
        SSL_CTX_free((SSL_CTX*)worker->ssl_ctx);
        worker->ssl_ctx = NULL;
    }
}

/**
 * Create a new connection context
 */
connection_ctx_t *connection_create(const char *host, int port, 
                                  const char *username, const char *password, 
                                  const char *domain) {
    connection_ctx_t *conn = calloc(1, sizeof(connection_ctx_t));
    if (!conn) {
        return NULL;
    }
    
    /* Initialize connection */
    conn->fd = -1;
    conn->state = CONN_STATE_INIT;
    conn->result = AUTH_RESULT_UNKNOWN;
    
    /* Set target address */
    conn->target.sin_family = AF_INET;
    conn->target.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &conn->target.sin_addr) != 1) {
        /* TODO: Handle hostname resolution */
        fprintf(stderr, "Invalid IP address: %s\n", host);
        free(conn);
        return NULL;
    }
    
    /* Allocate buffers */
    conn->recv_buffer = malloc(BUFFER_SIZE);
    conn->send_buffer = malloc(BUFFER_SIZE);
    if (!conn->recv_buffer || !conn->send_buffer) {
        connection_destroy(conn);
        return NULL;
    }
    
    /* Copy credentials */
    conn->username = strdup(username ? username : "");
    conn->password = strdup(password ? password : "");
    conn->domain = strdup(domain ? domain : "");
    
    /* Initialize timing */
    gettimeofday(&conn->start_time, NULL);
    
    return conn;
}

/**
 * Destroy connection context
 */
void connection_destroy(connection_ctx_t *conn) {
    if (!conn) return;
    
    if (conn->fd > 0) {
        close(conn->fd);
    }
    
    if (conn->ssl) {
        SSL_shutdown((SSL*)conn->ssl);
        SSL_free((SSL*)conn->ssl);
    }
    
    free(conn->recv_buffer);
    free(conn->send_buffer);
    free(conn->username);
    free(conn->password);
    free(conn->domain);
    
    if (conn->ts_request) {
        free(conn->ts_request->nego_tokens);
        free(conn->ts_request->auth_info);
        free(conn->ts_request->pub_key_auth);
        free(conn->ts_request);
    }
    
    if (conn->ts_response) {
        free(conn->ts_response->nego_tokens);
        free(conn->ts_response->auth_info);
        free(conn->ts_response->pub_key_auth);
        free(conn->ts_response);
    }
    
    credsp_cleanup(conn);
    
    free(conn);
}

/**
 * Make socket non-blocking
 */
int make_socket_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return -1;
    }
    
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL O_NONBLOCK");
        return -1;
    }
    
    return 0;
}

/**
 * Set socket options for performance
 */
int set_socket_options(int fd) {
    int opt = 1;
    
    /* Enable TCP_NODELAY */
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        perror("setsockopt TCP_NODELAY");
        return -1;
    }
    
    /* Set socket buffer sizes */
    int buf_size = 65536;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("setsockopt SO_RCVBUF");
    }
    
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("setsockopt SO_SNDBUF");
    }
    
    return 0;
}

/**
 * Calculate time difference in seconds
 */
double get_time_diff(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_usec - start->tv_usec) / 1000000.0;
}

/**
 * Print connection statistics
 */
void print_connection_stats(connection_ctx_t *conn) {
    if (!g_config->verbose) return;
    
    struct timeval now;
    gettimeofday(&now, NULL);
    double duration = get_time_diff(&conn->start_time, &now);
    
    printf("Connection %s:%d - %s (%.3fs)\n",
           inet_ntoa(conn->target.sin_addr),
           ntohs(conn->target.sin_port),
           conn->result == AUTH_RESULT_SUCCESS ? "SUCCESS" :
           conn->result == AUTH_RESULT_FAILED ? "FAILED" :
           conn->result == AUTH_RESULT_TIMEOUT ? "TIMEOUT" : "ERROR",
           duration);
}

/**
 * Print worker statistics
 */
void print_worker_stats(worker_ctx_t *worker) {
    printf("Worker %d: processed=%lu, success=%lu, failed=%lu, timeouts=%lu, errors=%lu\n",
           worker->thread_id,
           worker->connections_processed,
           worker->auth_success,
           worker->auth_failed,
           worker->timeouts,
           worker->errors);
}

/**
 * Print global statistics
 */
void print_global_stats(checker_stats_t *stats) {
    printf("\n=== RDP NLA Checker Statistics ===\n");
    printf("Total attempts: %lu\n", stats->total_attempts);
    printf("Successful auths: %lu\n", stats->successful_auths);
    printf("Failed auths: %lu\n", stats->failed_auths);
    printf("Timeouts: %lu\n", stats->timeouts);
    printf("Errors: %lu\n", stats->errors);
    printf("Duration: %.2f seconds\n", stats->duration);
    printf("Handshakes per second: %.2f\n", stats->handshakes_per_second);
    printf("Average handshake time: %.3f ms\n", stats->avg_handshake_time * 1000);
    printf("Average auth time: %.3f ms\n", stats->avg_auth_time * 1000);
    printf("==================================\n");
}

/**
 * Connect to target
 */
int connection_connect(connection_ctx_t *conn) {
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd < 0) {
        perror("socket");
        return -1;
    }
    
    if (make_socket_nonblocking(conn->fd) < 0) {
        close(conn->fd);
        conn->fd = -1;
        return -1;
    }
    
    if (set_socket_options(conn->fd) < 0) {
        close(conn->fd);
        conn->fd = -1;
        return -1;
    }
    
    int ret = connect(conn->fd, (struct sockaddr*)&conn->target, sizeof(conn->target));
    if (ret == 0) {
        /* Connected immediately */
        conn->state = CONN_STATE_TLS_HANDSHAKING;
        return 0;
    } else if (errno == EINPROGRESS) {
        /* Connection in progress */
        conn->state = CONN_STATE_TCP_CONNECTING;
        return 0;
    } else {
        perror("connect");
        close(conn->fd);
        conn->fd = -1;
        return -1;
    }
}

/**
 * Perform TLS handshake
 */
int connection_tls_handshake(connection_ctx_t *conn) {
    /* This is a simplified implementation - real TLS handshake would be more complex */
    conn->state = CONN_STATE_CREDSP_AUTH;
    return 0;
}

/**
 * Run the epoll-based checker
 */
int run_epoll_checker(checker_config_t *config) {
    printf("Starting epoll+OpenSSL checker with %d threads\n", config->num_threads);
    
    /* Initialize workers */
    for (int i = 0; i < config->num_threads; i++) {
        worker_ctx_t *worker = &g_workers[i];
        worker->thread_id = i;
        
        /* Create epoll instance */
        worker->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (worker->epoll_fd < 0) {
            perror("epoll_create1");
            return -1;
        }
        
        /* Setup SSL context */
        if (setup_ssl_context(worker) < 0) {
            return -1;
        }
        
        /* Initialize mutex */
        if (pthread_mutex_init(&worker->pool_mutex, NULL) != 0) {
            perror("pthread_mutex_init");
            return -1;
        }
        
        /* Create worker thread */
        if (pthread_create(&worker->thread, NULL, (void*)epoll_worker_loop, worker) != 0) {
            perror("pthread_create");
            return -1;
        }
        
        /* Set CPU affinity if requested */
        if (config->cpu_affinity && config->cpu_cores) {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(config->cpu_cores[i % config->num_threads], &cpuset);
            pthread_setaffinity_np(worker->thread, sizeof(cpu_set_t), &cpuset);
        }
    }
    
    /* Wait for completion */
    while (!g_shutdown) {
        sleep(1);
        
        /* Print periodic statistics */
        if (config->verbose) {
            for (int i = 0; i < config->num_threads; i++) {
                print_worker_stats(&g_workers[i]);
            }
        }
    }
    
    /* Calculate final statistics */
    g_stats.end_time = time(NULL);
    g_stats.duration = g_stats.end_time - g_stats.start_time;
    
    for (int i = 0; i < config->num_threads; i++) {
        worker_ctx_t *worker = &g_workers[i];
        g_stats.total_attempts += worker->connections_processed;
        g_stats.successful_auths += worker->auth_success;
        g_stats.failed_auths += worker->auth_failed;
        g_stats.timeouts += worker->timeouts;
        g_stats.errors += worker->errors;
    }
    
    if (g_stats.duration > 0) {
        g_stats.handshakes_per_second = g_stats.total_attempts / g_stats.duration;
    }
    
    print_global_stats(&g_stats);
    
    return 0;
}

/**
 * Worker thread main loop for epoll
 */
int epoll_worker_loop(void *arg) {
    worker_ctx_t *worker = (worker_ctx_t*)arg;
    struct epoll_event events[64];
    
    printf("Worker %d started\n", worker->thread_id);
    
    /* Create initial connections */
    for (int i = 0; i < g_config->max_concurrent / g_config->num_threads; i++) {
        int target_idx = (worker->thread_id * g_config->max_concurrent / g_config->num_threads + i) % g_config->num_targets;
        int user_idx = i % g_config->num_usernames;
        int pass_idx = i % g_config->num_passwords;
        
        connection_ctx_t *conn = connection_create(
            g_config->target_hosts[target_idx],
            g_config->target_ports[target_idx],
            g_config->usernames[user_idx],
            g_config->passwords[pass_idx],
            g_config->domains ? g_config->domains[0] : "" // Simplified domain handling
        );
        
        if (conn && connection_connect(conn) == 0) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | (g_config->edge_triggered ? EPOLLET : 0);
            ev.data.ptr = conn;
            epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, conn->fd, &ev);
            
            conn->next = worker->active_connections;
            worker->active_connections = conn;
        }
    }
    
    /* Main event loop */
    while (!g_shutdown) {
        int nfds = epoll_wait(worker->epoll_fd, events, 64, 1000);
        
        for (int i = 0; i < nfds; i++) {
            connection_ctx_t *conn = (connection_ctx_t*)events[i].data.ptr;
            
            if (epoll_handle_connection(conn, worker) < 0) {
                /* Connection completed or failed */
                epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                
                /* Remove from active list */
                if (worker->active_connections == conn) {
                    worker->active_connections = conn->next;
                } else {
                    connection_ctx_t *prev = worker->active_connections;
                    while (prev && prev->next != conn) {
                        prev = prev->next;
                    }
                    if (prev) {
                        prev->next = conn->next;
                    }
                }
                
                /* Update statistics */
                worker->connections_processed++;
                switch (conn->result) {
                    case AUTH_RESULT_SUCCESS:
                        worker->auth_success++;
                        break;
                    case AUTH_RESULT_FAILED:
                        worker->auth_failed++;
                        break;
                    case AUTH_RESULT_TIMEOUT:
                        worker->timeouts++;
                        break;
                    default:
                        worker->errors++;
                        break;
                }
                
                print_connection_stats(conn);
                connection_destroy(conn);
            }
        }
    }
    
    printf("Worker %d finished\n", worker->thread_id);
    return 0;
}

/**
 * Handle connection in epoll loop
 */
int epoll_handle_connection(connection_ctx_t *conn, worker_ctx_t *worker) {
    (void)worker;
    switch (conn->state) {
        case CONN_STATE_TCP_CONNECTING:
            /* Check if connection completed */
            int error;
            socklen_t len = sizeof(error);
            if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                conn->result = AUTH_RESULT_ERROR;
                return -1;
            }
            if (error != 0) {
                conn->result = AUTH_RESULT_ERROR;
                return -1;
            }
            conn->state = CONN_STATE_TLS_HANDSHAKING;
            /* Fall through */
            
        case CONN_STATE_TLS_HANDSHAKING:
            if (connection_tls_handshake(conn) < 0) {
                conn->result = AUTH_RESULT_ERROR;
                return -1;
            }
            /* Fall through */
            
        case CONN_STATE_CREDSP_AUTH:
            if (credsp_authenticate(conn) < 0) {
                conn->result = AUTH_RESULT_FAILED;
                return -1;
            }
            conn->state = CONN_STATE_COMPLETED;
            conn->result = AUTH_RESULT_SUCCESS;
            return -1; /* Signal completion */
            
        default:
            conn->result = AUTH_RESULT_ERROR;
            return -1;
    }
    
    return 0; /* Continue processing */
}

/**
 * Main entry point
 */
int main(int argc, char **argv) {
    checker_config_t config = {0};
    
    /* Default configuration */
    config.use_dpdk = false;
    config.num_threads = 4;
    config.max_concurrent = 1000;
    config.timeout_seconds = 30;
    config.edge_triggered = true;
    config.verbose = true;
    
    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dpdk") == 0) {
            config.use_dpdk = true;
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            config.num_threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--concurrent") == 0 && i + 1 < argc) {
            config.max_concurrent = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            config.timeout_seconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--targets") == 0 && i + 1 < argc) {
            if (parse_targets_file(argv[++i], &config) != 0) {
                fprintf(stderr, "Failed to parse targets file\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--users") == 0 && i + 1 < argc) {
            if (parse_users_file(argv[++i], &config) != 0) {
                fprintf(stderr, "Failed to parse users file\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--passwords") == 0 && i + 1 < argc) {
            if (parse_passwords_file(argv[++i], &config) != 0) {
                fprintf(stderr, "Failed to parse passwords file\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --dpdk                Use DPDK kernel-bypass\n");
            printf("  --threads N           Number of worker threads (default: 4)\n");
            printf("  --concurrent N        Max concurrent connections (default: 1000)\n");
            printf("  --timeout N           Timeout in seconds (default: 30)\n");
            printf("  --targets FILE        File with target hosts\n");
            printf("  --users FILE          File with usernames\n");
            printf("  --passwords FILE      File with passwords\n");
            printf("  --help               Show this help\n");
            return 0;
        }
    }
    
    /* Initialize dummy targets and credentials for testing */
    static char *targets[] = {"192.168.1.100", "192.168.1.101"};
    static int ports[] = {3389, 3389};
    static char *usernames[] = {"administrator", "admin", "test"};
    static char *passwords[] = {"password", "admin", "123456"};
    static char *domains[] = {"", "WORKGROUP", "DOMAIN"};
    
    config.target_hosts = targets;
    config.target_ports = ports;
    config.num_targets = 2;
    config.usernames = usernames;
    config.passwords = passwords;
    config.domains = domains;
    config.num_usernames = 3;
    config.num_passwords = 3;
    config.num_domains = 3;
    
    /* Initialize checker */
    if (rdp_checker_init(&config) < 0) {
        fprintf(stderr, "Failed to initialize RDP checker\n");
        return 1;
    }

    /* Initialize GSSAPI token pool */
    gssapi_token_pool_init();
    
    /* Run checker */
    int result;
    if (config.use_dpdk) {
        result = run_dpdk_checker(&config);
    } else {
        result = run_epoll_checker(&config);
    }
    
    /* Cleanup */
    gssapi_token_pool_cleanup();
    rdp_checker_cleanup();
    
    return result;
}

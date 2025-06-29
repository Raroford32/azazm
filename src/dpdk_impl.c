#include <stdio.h>
#include "rdp_nla_checker.h"

#ifdef USE_DPDK

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>

/* DPDK includes */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_cycles.h>

/* DPDK configuration */
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_PKT_BURST 32

/* TCP/IP constants */
#define ETHERNET_HEADER_SIZE 14
#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20
#define TCP_SYN_FLAG 0x02
#define TCP_ACK_FLAG 0x10
#define TCP_FIN_FLAG 0x01

/* Connection tracking */
typedef struct dpdk_connection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t state;
    uint64_t last_seen;
    connection_ctx_t *app_conn;
    struct dpdk_connection *next;
} dpdk_connection_t;

/* DPDK worker context */
typedef struct dpdk_worker {
    int lcore_id;
    int port_id;
    int queue_id;
    struct rte_mempool *mbuf_pool;
    struct rte_ring *conn_ring;
    dpdk_connection_t *conn_table[65536];  /* Hash table */
    uint64_t stats_packets_rx;
    uint64_t stats_packets_tx;
    uint64_t stats_connections;
    uint64_t stats_handshakes;
} dpdk_worker_t;

/* Global DPDK state */
static struct rte_mempool *g_mbuf_pool = NULL;
static dpdk_worker_t *g_dpdk_workers = NULL;
static int g_num_dpdk_workers = 0;
static volatile bool g_dpdk_shutdown = false;

/* Crypto device configuration */
static uint8_t g_crypto_dev_id = 0;
static struct rte_cryptodev_config g_crypto_config;
static struct rte_crypto_op_pool *g_crypto_op_pool = NULL;

/* Function declarations */
static int dpdk_port_init(uint16_t port, struct rte_mempool *mbuf_pool);
static int dpdk_crypto_init(void);
static uint32_t dpdk_hash_connection(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);
static dpdk_connection_t *dpdk_find_connection(dpdk_worker_t *worker, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);
static dpdk_connection_t *dpdk_create_connection(dpdk_worker_t *worker, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);
static void dpdk_destroy_connection(dpdk_worker_t *worker, dpdk_connection_t *conn);
static int dpdk_process_packet(dpdk_worker_t *worker, struct rte_mbuf *pkt);
static int dpdk_send_tcp_packet(dpdk_worker_t *worker, dpdk_connection_t *conn, uint8_t flags, uint8_t *payload, uint16_t payload_len);
static int dpdk_tls_handshake_offload(dpdk_worker_t *worker, dpdk_connection_t *conn);

/**
 * Initialize DPDK
 */
int dpdk_init(checker_config_t *config) {
    int ret;
    uint16_t nb_ports;
    
    printf("Initializing DPDK...\n");
    
    /* Check if DPDK is available */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        fprintf(stderr, "No Ethernet ports available\n");
        return -1;
    }
    
    printf("Found %u Ethernet ports\n", nb_ports);
    
    /* Create mbuf pool */
    g_mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                                         MBUF_CACHE_SIZE, 0,
                                         RTE_MBUF_DEFAULT_BUF_SIZE,
                                         rte_socket_id());
    
    if (g_mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    
    /* Initialize crypto device */
    if (config->hardware_crypto && dpdk_crypto_init() < 0) {
        fprintf(stderr, "Failed to initialize crypto device, continuing without hardware crypto\n");
        config->hardware_crypto = false;
    }
    
    /* Initialize port */
    if (dpdk_port_init(config->dpdk_port_id, g_mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", config->dpdk_port_id);
    }
    
    /* Allocate worker contexts */
    g_num_dpdk_workers = rte_lcore_count() - 1; /* Exclude master lcore */
    if (g_num_dpdk_workers <= 0) {
        fprintf(stderr, "No worker lcores available\n");
        return -1;
    }
    
    g_dpdk_workers = calloc(g_num_dpdk_workers, sizeof(dpdk_worker_t));
    if (!g_dpdk_workers) {
        fprintf(stderr, "Failed to allocate DPDK worker contexts\n");
        return -1;
    }
    
    /* Initialize worker contexts */
    int worker_idx = 0;
    RTE_LCORE_FOREACH_SLAVE(ret) {
        dpdk_worker_t *worker = &g_dpdk_workers[worker_idx];
        worker->lcore_id = ret;
        worker->port_id = config->dpdk_port_id;
        worker->queue_id = worker_idx % rte_eth_dev_info_get(config->dpdk_port_id, NULL)->max_rx_queues;
        worker->mbuf_pool = g_mbuf_pool;
        
        /* Create connection ring */
        char ring_name[32];
        snprintf(ring_name, sizeof(ring_name), "conn_ring_%d", worker_idx);
        worker->conn_ring = rte_ring_create(ring_name, 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!worker->conn_ring) {
            fprintf(stderr, "Failed to create connection ring for worker %d\n", worker_idx);
            return -1;
        }
        
        worker_idx++;
    }
    
    printf("DPDK initialization completed with %d workers\n", g_num_dpdk_workers);
    return 0;
}

/**
 * Initialize port
 */
static int dpdk_port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = {};
    const uint16_t rx_rings = g_num_dpdk_workers;
    const uint16_t tx_rings = g_num_dpdk_workers;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    
    if (!rte_eth_dev_is_valid_port(port)) {
        return -1;
    }
    
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
        return retval;
    }
    
    /* Configure the Ethernet device */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        return retval;
    }
    
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) {
        return retval;
    }
    
    /* Allocate and set up RX queues */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                       rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) {
            return retval;
        }
    }
    
    /* Setup TX queues */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                       rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) {
            return retval;
        }
    }
    
    /* Start the Ethernet port */
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        return retval;
    }
    
    /* Enable promiscuous mode */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0) {
        return retval;
    }
    
    return 0;
}

/**
 * Initialize crypto device
 */
static int dpdk_crypto_init(void) {
    uint8_t nb_devs;
    int ret;
    
    /* Check for crypto devices */
    nb_devs = rte_cryptodev_count();
    if (nb_devs == 0) {
        printf("No crypto devices available\n");
        return -1;
    }
    
    printf("Found %u crypto devices\n", nb_devs);
    
    /* Use first available crypto device */
    g_crypto_dev_id = 0;
    
    /* Configure crypto device */
    g_crypto_config.socket_id = rte_socket_id();
    g_crypto_config.nb_queue_pairs = 1;
    
    ret = rte_cryptodev_configure(g_crypto_dev_id, &g_crypto_config);
    if (ret < 0) {
        printf("Failed to configure crypto device %u\n", g_crypto_dev_id);
        return -1;
    }
    
    /* Setup queue pair */
    struct rte_cryptodev_qp_conf qp_conf;
    qp_conf.nb_descriptors = 1024;
    qp_conf.mp_session = NULL;
    qp_conf.mp_session_private = NULL;
    
    ret = rte_cryptodev_queue_pair_setup(g_crypto_dev_id, 0, &qp_conf, rte_socket_id());
    if (ret < 0) {
        printf("Failed to setup crypto queue pair\n");
        return -1;
    }
    
    /* Start crypto device */
    ret = rte_cryptodev_start(g_crypto_dev_id);
    if (ret < 0) {
        printf("Failed to start crypto device\n");
        return -1;
    }
    
    /* Create crypto operation pool */
    g_crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
                                                RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                                                1024, 128,
                                                0, rte_socket_id());
    if (!g_crypto_op_pool) {
        printf("Failed to create crypto operation pool\n");
        return -1;
    }
    
    printf("Crypto device initialized successfully\n");
    return 0;
}

/**
 * Hash function for connection table
 */
static uint32_t dpdk_hash_connection(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    return (src_ip ^ dst_ip ^ src_port ^ dst_port) & 0xFFFF;
}

/**
 * Find connection in hash table
 */
static dpdk_connection_t *dpdk_find_connection(dpdk_worker_t *worker, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    uint32_t hash = dpdk_hash_connection(src_ip, src_port, dst_ip, dst_port);
    dpdk_connection_t *conn = worker->conn_table[hash];
    
    while (conn) {
        if (conn->src_ip == src_ip && conn->src_port == src_port &&
            conn->dst_ip == dst_ip && conn->dst_port == dst_port) {
            return conn;
        }
        conn = conn->next;
    }
    
    return NULL;
}

/**
 * Create new connection
 */
static dpdk_connection_t *dpdk_create_connection(dpdk_worker_t *worker, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    dpdk_connection_t *conn = malloc(sizeof(dpdk_connection_t));
    if (!conn) {
        return NULL;
    }
    
    memset(conn, 0, sizeof(dpdk_connection_t));
    conn->src_ip = src_ip;
    conn->src_port = src_port;
    conn->dst_ip = dst_ip;
    conn->dst_port = dst_port;
    conn->last_seen = rte_rdtsc();
    
    /* Add to hash table */
    uint32_t hash = dpdk_hash_connection(src_ip, src_port, dst_ip, dst_port);
    conn->next = worker->conn_table[hash];
    worker->conn_table[hash] = conn;
    
    worker->stats_connections++;
    
    return conn;
}

/**
 * Destroy connection
 */
static void dpdk_destroy_connection(dpdk_worker_t *worker, dpdk_connection_t *conn) {
    if (!conn) return;
    
    /* Remove from hash table */
    uint32_t hash = dpdk_hash_connection(conn->src_ip, conn->src_port, conn->dst_ip, conn->dst_port);
    dpdk_connection_t **head = &worker->conn_table[hash];
    
    while (*head) {
        if (*head == conn) {
            *head = conn->next;
            break;
        }
        head = &(*head)->next;
    }
    
    if (conn->app_conn) {
        connection_destroy(conn->app_conn);
    }
    
    free(conn);
}

/**
 * Run DPDK checker
 */
int run_dpdk_checker(checker_config_t *config) {
    int ret;
    
    printf("Starting DPDK checker with %d workers\n", g_num_dpdk_workers);
    
    /* Launch worker threads on slave lcores */
    int worker_idx = 0;
    RTE_LCORE_FOREACH_SLAVE(ret) {
        rte_eal_remote_launch(dpdk_worker_loop, &g_dpdk_workers[worker_idx], ret);
        worker_idx++;
    }
    
    /* Main monitoring loop */
    while (!g_dpdk_shutdown) {
        sleep(1);
        
        /* Print statistics */
        if (config->verbose) {
            uint64_t total_rx = 0, total_tx = 0, total_conn = 0, total_hs = 0;
            
            for (int i = 0; i < g_num_dpdk_workers; i++) {
                dpdk_worker_t *worker = &g_dpdk_workers[i];
                total_rx += worker->stats_packets_rx;
                total_tx += worker->stats_packets_tx;
                total_conn += worker->stats_connections;
                total_hs += worker->stats_handshakes;
            }
            
            printf("DPDK Stats: RX=%lu, TX=%lu, Connections=%lu, Handshakes=%lu\n",
                   total_rx, total_tx, total_conn, total_hs);
        }
    }
    
    /* Wait for workers to finish */
    RTE_LCORE_FOREACH_SLAVE(ret) {
        if (rte_eal_wait_lcore(ret) < 0) {
            return -1;
        }
    }
    
    return 0;
}

/**
 * DPDK worker main loop
 */
int dpdk_worker_loop(void *arg) {
    dpdk_worker_t *worker = (dpdk_worker_t*)arg;
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx;
    
    printf("DPDK worker %d started on lcore %d\n", worker - g_dpdk_workers, worker->lcore_id);
    
    while (!g_dpdk_shutdown) {
        /* Receive packets */
        nb_rx = rte_eth_rx_burst(worker->port_id, worker->queue_id, bufs, BURST_SIZE);
        
        if (nb_rx == 0) {
            continue;
        }
        
        worker->stats_packets_rx += nb_rx;
        
        /* Process packets */
        for (uint16_t i = 0; i < nb_rx; i++) {
            if (dpdk_process_packet(worker, bufs[i]) < 0) {
                /* Error processing packet */
            }
            rte_pktmbuf_free(bufs[i]);
        }
        
        /* TODO: Cleanup old connections */
        /* TODO: Process connection ring for new outbound connections */
    }
    
    printf("DPDK worker %d finished\n", worker - g_dpdk_workers);
    return 0;
}

/**
 * Process received packet
 */
static int dpdk_process_packet(dpdk_worker_t *worker, struct rte_mbuf *pkt) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t tcp_flags;
    
    /* Parse Ethernet header */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        return -1; /* Not IPv4 */
    }
    
    /* Parse IP header */
    ip_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
    if (ip_hdr->next_proto_id != IPPROTO_TCP) {
        return -1; /* Not TCP */
    }
    
    src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);
    dst_ip = rte_be_to_cpu_32(ip_hdr->dst_addr);
    
    /* Parse TCP header */
    tcp_hdr = (struct rte_tcp_hdr *)((char *)ip_hdr + (ip_hdr->version_ihl & 0x0F) * 4);
    src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
    dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
    tcp_flags = tcp_hdr->tcp_flags;
    
    /* Check if this is an RDP connection (port 3389) */
    if (dst_port != 3389 && src_port != 3389) {
        return -1; /* Not RDP */
    }
    
    /* Find or create connection */
    dpdk_connection_t *conn = dpdk_find_connection(worker, src_ip, src_port, dst_ip, dst_port);
    if (!conn && (tcp_flags & TCP_SYN_FLAG)) {
        conn = dpdk_create_connection(worker, src_ip, src_port, dst_ip, dst_port);
        if (!conn) {
            return -1;
        }
    }
    
    if (!conn) {
        return -1; /* Unknown connection */
    }
    
    conn->last_seen = rte_rdtsc();
    
    /* Handle TCP state machine */
    if (tcp_flags & TCP_SYN_FLAG) {
        /* SYN packet - start of handshake */
        conn->seq_num = rte_be_to_cpu_32(tcp_hdr->sent_seq);
        conn->state = 1; /* SYN_RECEIVED */
        
        /* Send SYN-ACK */
        dpdk_send_tcp_packet(worker, conn, TCP_SYN_FLAG | TCP_ACK_FLAG, NULL, 0);
        
    } else if (tcp_flags & TCP_ACK_FLAG && conn->state == 1) {
        /* ACK packet - complete TCP handshake */
        conn->ack_num = rte_be_to_cpu_32(tcp_hdr->recv_ack);
        conn->state = 2; /* ESTABLISHED */
        
        /* Start TLS handshake */
        if (dpdk_tls_handshake_offload(worker, conn) < 0) {
            dpdk_destroy_connection(worker, conn);
            return -1;
        }
        
        worker->stats_handshakes++;
        
    } else if (tcp_flags & TCP_FIN_FLAG) {
        /* FIN packet - close connection */
        dpdk_destroy_connection(worker, conn);
    }
    
    return 0;
}

/**
 * Send TCP packet
 */
static int dpdk_send_tcp_packet(dpdk_worker_t *worker, dpdk_connection_t *conn, uint8_t flags, uint8_t *payload, uint16_t payload_len) {
    struct rte_mbuf *pkt;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    uint16_t pkt_len;
    
    /* Allocate mbuf */
    pkt = rte_pktmbuf_alloc(worker->mbuf_pool);
    if (!pkt) {
        return -1;
    }
    
    pkt_len = ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE + payload_len;
    
    /* Build Ethernet header */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    /* TODO: Fill in MAC addresses */
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    
    /* Build IP header */
    ip_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + ETHERNET_HEADER_SIZE);
    ip_hdr->version_ihl = 0x45; /* IPv4, 20-byte header */
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(IP_HEADER_SIZE + TCP_HEADER_SIZE + payload_len);
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_TCP;
    ip_hdr->src_addr = rte_cpu_to_be_32(conn->dst_ip); /* Swap for response */
    ip_hdr->dst_addr = rte_cpu_to_be_32(conn->src_ip);
    ip_hdr->hdr_checksum = 0;
    
    /* Build TCP header */
    tcp_hdr = (struct rte_tcp_hdr *)((char *)ip_hdr + IP_HEADER_SIZE);
    tcp_hdr->src_port = rte_cpu_to_be_16(conn->dst_port); /* Swap for response */
    tcp_hdr->dst_port = rte_cpu_to_be_16(conn->src_port);
    tcp_hdr->sent_seq = rte_cpu_to_be_32(conn->seq_num + 1);
    tcp_hdr->recv_ack = rte_cpu_to_be_32(conn->ack_num + 1);
    tcp_hdr->data_off = 0x50; /* 20-byte header */
    tcp_hdr->tcp_flags = flags;
    tcp_hdr->rx_win = rte_cpu_to_be_16(65535);
    tcp_hdr->cksum = 0;
    tcp_hdr->tcp_urp = 0;
    
    /* Copy payload */
    if (payload && payload_len > 0) {
        rte_memcpy((char *)tcp_hdr + TCP_HEADER_SIZE, payload, payload_len);
    }
    
    pkt->data_len = pkt_len;
    pkt->pkt_len = pkt_len;
    
    /* Send packet */
    uint16_t sent = rte_eth_tx_burst(worker->port_id, worker->queue_id, &pkt, 1);
    if (sent == 0) {
        rte_pktmbuf_free(pkt);
        return -1;
    }
    
    worker->stats_packets_tx++;
    return 0;
}

/**
 * Perform TLS handshake with hardware offload
 */
static int dpdk_tls_handshake_offload(dpdk_worker_t *worker, dpdk_connection_t *conn) {
    /* Simplified implementation - in real scenario this would use crypto device */
    
    if (g_crypto_op_pool) {
        /* Use hardware crypto offload */
        struct rte_crypto_op *op;
        
        /* Allocate crypto operation */
        op = rte_crypto_op_alloc(g_crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
        if (!op) {
            return -1;
        }
        
        /* Configure crypto operation for TLS */
        /* TODO: Setup actual crypto parameters */
        
        /* Enqueue operation */
        if (rte_cryptodev_enqueue_burst(g_crypto_dev_id, 0, &op, 1) != 1) {
            rte_crypto_op_free(op);
            return -1;
        }
        
        /* Poll for completion */
        struct rte_crypto_op *processed_op;
        while (rte_cryptodev_dequeue_burst(g_crypto_dev_id, 0, &processed_op, 1) == 0) {
            /* Wait for completion */
        }
        
        if (processed_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
            rte_crypto_op_free(processed_op);
            return -1;
        }
        
        rte_crypto_op_free(processed_op);
    }
    
    /* Create application-level connection context */
    char src_ip_str[16], dst_ip_str[16];
    sprintf(src_ip_str, "%u.%u.%u.%u", 
            (conn->src_ip >> 24) & 0xFF, (conn->src_ip >> 16) & 0xFF,
            (conn->src_ip >> 8) & 0xFF, conn->src_ip & 0xFF);
    sprintf(dst_ip_str, "%u.%u.%u.%u",
            (conn->dst_ip >> 24) & 0xFF, (conn->dst_ip >> 16) & 0xFF,
            (conn->dst_ip >> 8) & 0xFF, conn->dst_ip & 0xFF);
    
    conn->app_conn = connection_create(dst_ip_str, conn->dst_port, "test", "test", "");
    if (!conn->app_conn) {
        return -1;
    }
    
    /* Perform CredSSP authentication */
    if (credsp_authenticate(conn->app_conn) < 0) {
        return -1;
    }
    
    return 0;
}

/**
 * DPDK connection handling (stub)
 */
int dpdk_handle_connection(connection_ctx_t *conn) {
    /* This function is called from the main checker loop */
    /* In DPDK mode, most work is done in the worker loop */
    return 0;
}

#else /* !USE_DPDK */

/* Stub functions when DPDK is not available */
int dpdk_init(checker_config_t *config) { (void)config; fprintf(stderr, "DPDK support not compiled in\n"); return -1; }
int run_dpdk_checker(checker_config_t *config) { (void)config; fprintf(stderr, "DPDK support not compiled in\n"); return -1; }
int dpdk_worker_loop(void *arg) { (void)arg; return -1; }
int dpdk_handle_connection(connection_ctx_t *conn) { (void)conn; return -1; }

#endif /* USE_DPDK */

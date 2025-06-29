/**
 * file_parser.c
 *
 * Implements file parsing functions for targets, users, passwords, and domains.
 *
 * Rationale: Efficiently loads large lists (up to 1M lines) for high-throughput credential checking.
 * Ensures all resources are freed and errors are reported clearly.
 *
 * Author: Auto-generated, reviewed for optimal performance and safety.
 * Date: June 29, 2025
 */

#include "rdp_nla_checker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINES 1000000
#define MAX_LINE_LEN 256

/**
 * Parse lines from a file into a dynamically allocated array of strings.
 *
 * filename: Path to file.
 * line_count: Output pointer for number of lines read.
 * Returns: Array of strings (caller must free each string and the array), or NULL on error.
 */
static char** parse_file_lines(const char *filename, int *line_count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    char **lines = malloc(MAX_LINES * sizeof(char*));
    if (!lines) {
        fclose(fp);
        return NULL;
    }

    char buffer[MAX_LINE_LEN];
    int count = 0;
    while (fgets(buffer, sizeof(buffer), fp) && count < MAX_LINES) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        if (strlen(buffer) > 0) {
            lines[count] = strdup(buffer);
            if (!lines[count]) {
                // Free previously allocated lines
                for (int j = 0; j < count; j++) free(lines[j]);
                free(lines);
                fclose(fp);
                return NULL;
            }
            count++;
        }
    }

    fclose(fp);
    *line_count = count;
    return lines;
}

/**
 * Parse targets file (host:port per line) into config.
 * Returns 0 on success, -1 on error.
 */
int parse_targets_file(const char *filename, checker_config_t *config) {
    int count = 0;
    char **lines = parse_file_lines(filename, &count);
    if (!lines) return -1;

    config->target_hosts = malloc(count * sizeof(char*));
    config->target_ports = malloc(count * sizeof(int));
    if (!config->target_hosts || !config->target_ports) {
        if (config->target_hosts) free(config->target_hosts);
        if (config->target_ports) free(config->target_ports);
        for (int i = 0; i < count; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        char *host = strtok(lines[i], ":");
        char *port_str = strtok(NULL, ":");
        config->target_hosts[i] = strdup(host);
        if (!config->target_hosts[i]) {
            // Free all previously allocated
            for (int j = 0; j < i; j++) free(config->target_hosts[j]);
            free(config->target_hosts);
            free(config->target_ports);
            for (int j = 0; j < count; j++) free(lines[j]);
            free(lines);
            return -1;
        }
        config->target_ports[i] = port_str ? atoi(port_str) : RDP_DEFAULT_PORT;
        free(lines[i]);
    }

    config->num_targets = count;
    free(lines);
    return 0;
}

/**
 * Parse users file (one username per line) into config.
 * Returns 0 on success, -1 on error.
 */
int parse_users_file(const char *filename, checker_config_t *config) {
    config->usernames = parse_file_lines(filename, &config->num_usernames);
    return config->usernames ? 0 : -1;
}

/**
 * Parse passwords file (one password per line) into config.
 * Returns 0 on success, -1 on error.
 */
int parse_passwords_file(const char *filename, checker_config_t *config) {
    config->passwords = parse_file_lines(filename, &config->num_passwords);
    return config->passwords ? 0 : -1;
}

/**
 * Parse domains file (one domain per line) into config.
 * Returns 0 on success, -1 on error.
 */
int parse_domains_file(const char *filename, checker_config_t *config) {
    config->domains = parse_file_lines(filename, &config->num_domains);
    return config->domains ? 0 : -1;
}

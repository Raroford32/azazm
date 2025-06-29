/**
 * CredSSP (Credential Security Support Provider) Implementation
 * 
 * Implements MS-CredSSP protocol for RDP NLA authentication
 * Supports NTLM and Kerberos authentication mechanisms
 */

#include "rdp_nla_checker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <gssapi/gssapi.h>
#include <errno.h>
#include <arpa/inet.h>

#ifndef HAVE_GSSAPI_NTLM_H
#define gss_mech_spnego GSS_C_NO_OID
#endif

/* Static function prototypes */
static int asn1_write_length(uint8_t **ptr, uint32_t length);
static int asn1_read_length(uint8_t **ptr, uint32_t *length);
static int asn1_read_integer(uint8_t **ptr, uint32_t *value, uint32_t length);

/* CredSSP protocol constants */
#define CREDSSP_SEQUENCE_TAG    0x30
#define CREDSSP_VERSION_TAG     0x02
#define CREDSSP_NEGO_TOKEN_TAG  0x30
#define CREDSSP_AUTH_INFO_TAG   0x30
#define CREDSSP_PUB_KEY_TAG     0x04

/**
 * Initialize CredSSP context for connection
 */
int credsp_init_context(connection_ctx_t *conn) {
    if (!conn) return -1;
    
    /* Allocate CredSSP structures */
    conn->ts_request = calloc(1, sizeof(ts_request_t));
    conn->ts_response = calloc(1, sizeof(ts_response_t));
    
    if (!conn->ts_request || !conn->ts_response) {
        credsp_cleanup(conn);
        return -1;
    }
    
    /* Set CredSSP version */
    conn->ts_request->version = CREDSP_VERSION;
    
    /* Initialize GSSAPI context */
    if (gssapi_init_context(conn) < 0) {
        credsp_cleanup(conn);
        return -1;
    }
    
    return 0;
}

/**
 * Create TSRequest message
 */
int credsp_create_ts_request(connection_ctx_t *conn) {
    if (!conn || !conn->ts_request) return -1;
    
    ts_request_t *req = conn->ts_request;
    
    /* Generate GSSAPI negotiation token */
    if (gssapi_create_nego_token(conn, &req->nego_tokens, &req->nego_tokens_len) < 0) {
        return -1;
    }
    
    /* For initial request, no auth info or pub key auth */
    req->auth_info = NULL;
    req->auth_info_len = 0;
    req->pub_key_auth = NULL;
    req->pub_key_auth_len = 0;
    
    return 0;
}

/**
 * Encode TSRequest to ASN.1 DER format directly into a provided buffer.
 * This avoids extra malloc/free calls in the hot path.
 */
int asn1_encode_ts_request(ts_request_t *req, uint8_t **out, uint32_t *out_len) {
    if (!req || !out || !out_len) return -1;
    
    uint8_t *ptr = *out;
    uint8_t *start = ptr;
    uint8_t *end = ptr + BUFFER_SIZE;

    /* TSRequest SEQUENCE */
    if (ptr + 2 > end) return -1; // Tag + length
    *ptr++ = CREDSSP_SEQUENCE_TAG;
    uint8_t *seq_len_ptr = ptr++;  /* Reserve space for length */
    uint8_t *seq_start = ptr;

    /* version [0] INTEGER */
    if (ptr + 5 > end) return -1; // Max integer size
    *ptr++ = 0xA0; // Context-specific tag [0]
    *ptr++ = 0x03; // Length of content
    *ptr++ = 0x02; // Type: INTEGER
    *ptr++ = 0x01; // Length: 1
    *ptr++ = (uint8_t)req->version;

    /* negoTokens [2] EXPLICIT SEQUENCE OPTIONAL */
    if (req->nego_tokens && req->nego_tokens_len > 0) {
        // Tag for negoTokens [2]
        if (ptr + 1 > end) return -1;
        *ptr++ = 0xA2;

        // Length of the entire negoTokens structure
        uint8_t *nego_len_ptr = ptr++;
        uint8_t *nego_start = ptr;

        // SEQUENCE of NegoToken
        if (ptr + 2 > end) return -1;
        *ptr++ = 0x30; // SEQUENCE
        uint8_t *nego_seq_len_ptr = ptr++;
        uint8_t *nego_seq_start = ptr;

        // NegoToken [0] OCTET STRING
        if (ptr + 1 > end) return -1;
        *ptr++ = 0xA0; // [0]
        uint8_t* token_len_ptr = ptr++;
        uint8_t* token_start = ptr;
        if (ptr + req->nego_tokens_len > end) return -1;
        memcpy(ptr, req->nego_tokens, req->nego_tokens_len);
        ptr += req->nego_tokens_len;
        *token_len_ptr = (uint8_t)(ptr - token_start);

        *nego_seq_len_ptr = (uint8_t)(ptr - nego_seq_start);
        *nego_len_ptr = (uint8_t)(ptr - nego_start);
    }

    /* pubKeyAuth [4] OCTET STRING OPTIONAL */
    if (req->pub_key_auth && req->pub_key_auth_len > 0) {
        if (ptr + 2 + req->pub_key_auth_len > end) return -1;
        *ptr++ = 0xA4;  /* [4] IMPLICIT */
        ptr += asn1_write_length(&ptr, req->pub_key_auth_len);
        memcpy(ptr, req->pub_key_auth, req->pub_key_auth_len);
        ptr += req->pub_key_auth_len;
    }

    /* Write final sequence length */
    uint32_t seq_len = ptr - seq_start;
    uint8_t *temp_ptr = seq_len_ptr;
    asn1_write_length(&temp_ptr, seq_len);
    // The pointer has been advanced by asn1_write_length, but we need to adjust the final ptr
    // This is tricky. Let's rewrite the length encoding to be more direct.
    if (seq_len < 128) {
        *seq_len_ptr = seq_len;
    } else {
        // This case is more complex and requires shifting data, 
        // for this high-speed checker, we assume the TSRequest is small.
        return -1; 
    }

    *out_len = ptr - start;
    return 0;
}

/**
 * Send TSRequest over TLS connection
 */
int credsp_send_ts_request(connection_ctx_t *conn) {
    if (!conn || !conn->ts_request) return -1;
    
    uint32_t encoded_len = 0;
    
    /* Encode TSRequest to ASN.1 DER directly into the connection's send buffer */
    if (asn1_encode_ts_request(conn->ts_request, &conn->send_buffer, &encoded_len) < 0) {
        fprintf(stderr, "Failed to encode TSRequest\n");
        return -1;
    }
    
    /* Send over TLS connection */
    int sent = 0;
    if (conn->ssl) {
        sent = SSL_write((SSL*)conn->ssl, conn->send_buffer, encoded_len);
    } else {
        /* Fallback to raw socket for testing */
        sent = send(conn->fd, conn->send_buffer, encoded_len, 0);
    }
    
    if (sent != (int)encoded_len) {
        fprintf(stderr, "Failed to send complete TSRequest\n");
        return -1;
    }
    
    return 0;
}

/**
 * Receive TSResponse from TLS connection
 */
int credsp_recv_ts_response(connection_ctx_t *conn) {
    if (!conn) return -1;
    
    int received = 0;
    if (conn->ssl) {
        received = SSL_read((SSL*)conn->ssl, conn->recv_buffer, BUFFER_SIZE);
    } else {
        /* Fallback to raw socket for testing */
        received = recv(conn->fd, conn->recv_buffer, BUFFER_SIZE, 0);
    }
    
    if (received <= 0) {
        if (conn->ssl) {
            int err = SSL_get_error((SSL*)conn->ssl, received);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return 0; /* Would block, try again later */
            }
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* Would block, try again later */
        }
        return -1;
    }
    
    conn->recv_len = received;
    
    /* Parse TSResponse */
    if (credsp_parse_ts_response(conn) < 0) {
        return -1;
    }
    
    return received;
}

/**
 * Parse TSResponse message
 */
int credsp_parse_ts_response(connection_ctx_t *conn) {
    if (!conn || !conn->recv_buffer || conn->recv_len == 0) return -1;
    
    /* Decode ASN.1 DER to TSResponse */
    if (asn1_decode_ts_response(conn->recv_buffer, conn->recv_len, conn->ts_response) < 0) {
        return -1;
    }
    
    /* Process GSSAPI response token */
    if (conn->ts_response->nego_tokens && conn->ts_response->nego_tokens_len > 0) {
        if (gssapi_process_response(conn, conn->ts_response->nego_tokens, 
                                   conn->ts_response->nego_tokens_len) < 0) {
            return -1;
        }
    }
    
    return 0;
}

/**
 * Perform CredSSP authentication
 */
int credsp_authenticate(connection_ctx_t *conn) {
    if (!conn) return -1;

    /* Initialize CredSSP context if not already done */
    if (!conn->ts_request && credsp_init_context(conn) < 0) {
        return -1;
    }

    OM_uint32 major_status = GSS_S_CONTINUE_NEEDED;
    int retries = 5; // Max handshake legs

    /* Main authentication loop to handle multi-stage handshake */
    while (major_status == GSS_S_CONTINUE_NEEDED && retries-- > 0) {
        /* Create and send TSRequest */
        if (credsp_create_ts_request(conn) < 0) {
            return -1;
        }

        if (credsp_send_ts_request(conn) < 0) {
            return -1;
        }

        /* Receive and parse TSResponse */
        int result = credsp_recv_ts_response(conn);
        if (result <= 0) {
            /* Handle timeout or error */
            fprintf(stderr, "Failed to receive TSResponse or connection closed\n");
            return -1;
        }

        /* Process GSSAPI response token, which updates major_status */
        if (conn->ts_response->nego_tokens && conn->ts_response->nego_tokens_len > 0) {
            major_status = gssapi_process_response(conn, conn->ts_response->nego_tokens, 
                                       conn->ts_response->nego_tokens_len);

            if (GSS_ERROR(major_status) && major_status != GSS_S_CONTINUE_NEEDED) {
                fprintf(stderr, "GSSAPI processing failed\n");
                return -1;
            }
        }
    }

    if (major_status != GSS_S_COMPLETE) {
        fprintf(stderr, "CredSSP authentication did not complete.\n");
        return -1;
    }

    /* Final check on server response */
    if (conn->ts_response->version != CREDSP_VERSION) {
        fprintf(stderr, "Invalid CredSSP version in response\n");
        return -1;
    }

    return 0; /* Authentication successful */
}

/**
 * Cleanup CredSSP resources
 */
void credsp_cleanup(connection_ctx_t *conn) {
    if (!conn) return;
    
    if (conn->gss_context) {
        OM_uint32 minor_status;
        gss_delete_sec_context(&minor_status, &conn->gss_context, GSS_C_NO_BUFFER);
        conn->gss_context = NULL;
    }
}

/**
 * Initialize GSSAPI context
 */
int gssapi_init_context(connection_ctx_t *conn) {
    if (!conn) return -1;
    
    /* For simplified implementation, we'll use NTLM */
#ifdef HAVE_GSSAPI_NTLM_H
    static gss_OID_desc ntlm_oid = {10, "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"};
    gss_OID mech_type = &ntlm_oid;
#endif
    
    /* Initialize security context */
    conn->gss_context = GSS_C_NO_CONTEXT;
    
    return 0;
}

/**
 * Create GSSAPI negotiation token (SPNEGO)
 */
int gssapi_create_nego_token(connection_ctx_t *conn, uint8_t **token, uint32_t *token_len) {
    if (!conn || !token || !token_len) return -1;

    OM_uint32 major_status, minor_status;
    gss_name_t target_name = GSS_C_NO_NAME;

    char target_spn[256];
    snprintf(target_spn, sizeof(target_spn), "TERMSRV/%s", inet_ntoa(conn->target.sin_addr));

    gss_buffer_desc spn_buffer;
    spn_buffer.value = target_spn;
    spn_buffer.length = strlen(target_spn);

    major_status = gss_import_name(&minor_status, &spn_buffer, GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (GSS_ERROR(major_status)) {
        return -1;
    }

    major_status = gss_init_sec_context(&minor_status,
                                      (gss_cred_id_t)GSS_C_NO_CREDENTIAL,
                                      &conn->gss_context,
                                      target_name,
                                      gss_mech_spnego,
                                      GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
                                      GSS_C_INDEFINITE,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &output_tok,
                                      NULL,
                                      NULL);

    gss_release_name(&minor_status, &target_name);

    if (GSS_ERROR(major_status) && major_status != GSS_S_CONTINUE_NEEDED) {
        return -1;
    }

    *token = gssapi_token_pool_get();
    if (!*token) {
        gss_release_buffer(&minor_status, &output_tok);
        return -1; // Pool exhausted
    }

    memcpy(*token, output_tok.value, output_tok.length);
    *token_len = output_tok.length;

    gss_release_buffer(&minor_status, &output_tok);

    return 0;
}

/**
 * Process GSSAPI response token (SPNEGO)
 */
int gssapi_process_response(connection_ctx_t *conn, uint8_t *token, uint32_t token_len) {
    if (!conn || !token || token_len == 0) return -1;

    OM_uint32 major_status, minor_status;
    gss_buffer_desc input_tok;
    input_tok.value = token;
    input_tok.length = token_len;
    gss_buffer_desc output_tok = GSS_C_EMPTY_BUFFER;

    major_status = gss_init_sec_context(&minor_status,
                                      (gss_cred_id_t)GSS_C_NO_CREDENTIAL,
                                      &conn->gss_context,
                                      GSS_C_NO_NAME,
                                      gss_mech_spnego,
                                      0,
                                      GSS_C_INDEFINITE,
                                      NULL,
                                      &input_tok,
                                      NULL,
                                      &output_tok,
                                      NULL,
                                      NULL);

    if (GSS_ERROR(major_status) && major_status != GSS_S_CONTINUE_NEEDED) {
        gss_release_buffer(&minor_status, &output_tok);
        return -1;
    }

    // Handle the output token if necessary (e.g., for the next leg of the authentication)
    if (output_tok.length > 0) {
        // This would be sent in the next TSRequest
        // Since we are not sending another token, we can release the buffer
        gssapi_token_pool_release(output_tok.value);
        gss_release_buffer(&minor_status, &output_tok);
    }

    return (major_status == GSS_S_COMPLETE) ? 0 : 1; // 1 if continue needed
}

/**
 * Decode ASN.1 DER to TSResponse
 */
int asn1_decode_ts_response(uint8_t *data, uint32_t len, ts_response_t *resp) {
    if (!data || len == 0 || !resp) return -1;
    
    uint8_t *ptr = data;
    uint8_t *end = data + len;
    
    /* Check SEQUENCE tag */
    if (ptr >= end || *ptr++ != CREDSSP_SEQUENCE_TAG) {
        return -1;
    }
    
    /* Read sequence length */
    uint32_t seq_len;
    if (asn1_read_length(&ptr, &seq_len) < 0) {
        return -1;
    }
    
    /* Read version */
    if (ptr >= end || *ptr++ != CREDSSP_VERSION_TAG) {
        return -1;
    }
    
    uint32_t version_len;
    if (asn1_read_length(&ptr, &version_len) < 0) {
        return -1;
    }
    
    if (asn1_read_integer(&ptr, &resp->version, version_len) < 0) {
        return -1;
    }
    
    /* Parse optional fields */
    while (ptr < end) {
        uint8_t tag = *ptr++;
        uint32_t field_len;
        
        if (asn1_read_length(&ptr, &field_len) < 0) {
            break;
        }
        
        switch (tag) {
            case 0xA0:  /* negoTokens [0] */
                resp->nego_tokens = malloc(field_len);
                if (resp->nego_tokens) {
                    memcpy(resp->nego_tokens, ptr, field_len);
                    resp->nego_tokens_len = field_len;
                }
                break;
                
            case 0xA1:  /* authInfo [1] */
                resp->auth_info = malloc(field_len);
                if (resp->auth_info) {
                    memcpy(resp->auth_info, ptr, field_len);
                    resp->auth_info_len = field_len;
                }
                break;
                
            case 0xA2:  /* pubKeyAuth [2] */
                resp->pub_key_auth = malloc(field_len);
                if (resp->pub_key_auth) {
                    memcpy(resp->pub_key_auth, ptr, field_len);
                    resp->pub_key_auth_len = field_len;
                }
                break;
        }
        
        ptr += field_len;
    }
    
    return 0;
}

/**
 * ASN.1 utility functions
 */
static int asn1_write_length(uint8_t **ptr, uint32_t length) {
    if (length < 0x80) {
        *(*ptr)++ = length;
        return 1;
    } else if (length < 0x100) {
        *(*ptr)++ = 0x81;
        *(*ptr)++ = length;
        return 2;
    } else if (length < 0x10000) {
        *(*ptr)++ = 0x82;
        *(*ptr)++ = length >> 8;
        *(*ptr)++ = length & 0xFF;
        return 3;
    } else {
        *(*ptr)++ = 0x83;
        *(*ptr)++ = length >> 16;
        *(*ptr)++ = (length >> 8) & 0xFF;
        *(*ptr)++ = length & 0xFF;
        return 4;
    }
}

static int asn1_read_length(uint8_t **ptr, uint32_t *length) {
    uint8_t first = *(*ptr)++;
    
    if (first < 0x80) {
        *length = first;
        return 1;
    } else {
        int num_bytes = first & 0x7F;
        if (num_bytes == 0 || num_bytes > 4) {
            return -1;
        }
        
        *length = 0;
        for (int i = 0; i < num_bytes; i++) {
            *length = (*length << 8) | *(*ptr)++;
        }
        return num_bytes + 1;
    }
}

static int asn1_write_integer(uint8_t **ptr, uint32_t value) {
    uint8_t buf[5];
    int len = 0;

    if (value == 0) {
        buf[len++] = 0;
    } else {
        uint32_t v = value;
        while (v > 0) {
            buf[len++] = v & 0xFF;
            v >>= 8;
        }
    }

    /* For unsigned integers, if the most significant bit of the most
     * significant byte is 1, a leading 0x00 is required by DER. */
    if ((buf[len - 1] & 0x80) != 0) {
        buf[len++] = 0x00;
    }

    /* Write the bytes in reverse order (big-endian) */
    uint8_t *p = *ptr;
    for (int i = len - 1; i >= 0; i--) {
        *p++ = buf[i];
    }
    *ptr = p;
    
    return len;
}

static int asn1_read_integer(uint8_t **ptr, uint32_t *value, uint32_t length) {
    if (length == 0 || length > 4) {
        /* This implementation supports up to 4-byte unsigned integers.
         * A zero-length integer is invalid DER. */
        return -1;
    }
    
    *value = 0;
    for (uint32_t i = 0; i < length; i++) {
        *value = (*value << 8) | *(*ptr)++;
    }
    return (int)length;
}

/* An optional add-on to the "sample" project.
 *
 * This implements a simple picoquic connection-splitting proxy.
 * The proxy is tied to a single pre-determined server (IP, port) that should
 * be specified in the CLI.
 *
 * Like the sample_server, the proxy listens for incoming connections.
 *
 * Upon receipt, the proxy opens a new picoquic connection to its assigned server.
 * It copies payloads from one socket to the other, performing
 * necessary decryption and re-encryption in between.
 *
 * The connection to the end-to-end connection's "client" (the peer who initiated the
 * end-to-end connection) is referred to as the "client" connection.
 * The connection to the backend server that the proxy initiates is the "server" connection.
 */

#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picosocks.h>
#include <picoquic_utils.h>
#include <autoqlog.h>
#include "picoquic_sample.h"
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"

/*
 * The direction of the connection.
 */
typedef enum st_sample_conn_type_t {
    // Connection is between the proxy and the end-to-end connection's client
    CLIENT,
    // Connection is between the proxy and the end-to-end connection's server
    SERVER,
} sample_conn_type_t;

/* Per-stream ctx passed into RX callback for each packet.
 * - In the callback, this is expected to be non-NULL for the server stream,
 *   as the proxy opens this stream and must create the stream context.
 *   For the client stream, it may be NULL if it is a new connection.
 */
typedef struct st_sample_proxy_stream_ctx_t {
    // Stream identifier, read from first packet (client-side) or
    // generated locally (server-side)
    uint64_t    stream_id;
    // Direction of the stream
    sample_conn_type_t stream_type;
} sample_proxy_stream_ctx_t;

/*
 * Per-pair context, where a "pair" is a pair of QUIC connections
 * -- one "client-side" and one "server-side" -- that the proxy is
 * forwarding data between.
 * Each QUIC cconnection is limited to a single stream.
 */
typedef struct st_sample_proxy_ctx_t {
    // QUIC stream identifiers
    uint64_t        client_stream_id;
    uint64_t        server_stream_id;
    // Pointer to the QUIC connection structures,
    // usable for sending data
    picoquic_cnx_t *client_cnx;
    picoquic_cnx_t *server_cnx;
} sample_proxy_ctx_t;

/*
 * A global variable to manage per-proxy context, limiting the proxy to
 * a single connection at a time.
 *
 * All read ops are JIT, and the client-side connection and context is NULL
 * until initiated by the client. It makes sense to have global state so that
 * when the RX CB is invoked in the server's context, it can access the client's
 * context, and vice verse.
 */
sample_proxy_ctx_t global_proxy_ctx = {
    .client_stream_id = 0,
    .server_stream_id = 0,
    .client_cnx = NULL,
    .server_cnx = NULL,
};

void print_cnx_info(picoquic_cnx_t* cnx, uint64_t stream_id) {
    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr* peer_addr;
    memset(ip_str, 0, INET_ADDRSTRLEN);
    picoquic_get_peer_addr(cnx, &peer_addr);

    if (peer_addr->sa_family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in *)peer_addr;
        uint8_t* addr = (uint8_t *)&s4->sin_addr;
        printf("Proxy received connection from %d.%d.%d.%d:%d (stream ID: %lu)\n",
            addr[0], addr[1], addr[2], addr[3],
            ntohs(s4->sin_port),
            stream_id);
    }
    else if (peer_addr->sa_family == AF_INET6) {
        fprintf(stderr, "IPv6 not supported");
    }
    else {
        fprintf(stderr, "Protocol is not IPv4 or IPv6: %hu", peer_addr->sa_family);
    }
}

/*
 * Will be invoked for each packet in either direction.
 * - If proxy_ctx and stream_ctx are NULL, this is expected to be
 *   an incoming client-side packet for a new connection.
 * - Stream_ctx will indicate whether this is from server or client cnx.
 * - Directly copies `bytes` to the queue of the peer cnx.
 */
int sample_proxy_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    sample_proxy_ctx_t* proxy_ctx = (sample_proxy_ctx_t *)callback_ctx;
    sample_proxy_stream_ctx_t* stream_ctx = (sample_proxy_stream_ctx_t *)v_stream_ctx;
    int ret = 0;

    // If this is the first reference to the connection, then we can assume it came from a
    // client that wants to be proxied to the server.
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        // Create context for the connection management
        if (global_proxy_ctx.server_cnx != NULL) {
            // Unknown new connection; warn of update
            fprintf(stderr, "Unknown new connection\n");
        }
        proxy_ctx = &global_proxy_ctx;
        global_proxy_ctx.server_cnx = cnx;
        picoquic_set_callback(cnx, sample_proxy_callback, proxy_ctx);
        print_cnx_info(cnx, stream_id);
    } else {
        if (callback_ctx != &global_proxy_ctx) {
            fprintf(stderr, "Unknown connection -- should have had global_proxy_ctx\n");
            return(-1);
        }
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        // Data arrival on stream, maybe with fin mark
        if (stream_ctx == NULL) {
            // Streams for the client were already set up; should never be NULL in this CB
            proxy_ctx->server_stream_id = stream_id;
            stream_ctx = (sample_proxy_stream_ctx_t*)malloc(sizeof(sample_proxy_stream_ctx_t));
            if (stream_ctx == NULL) {
                (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                fprintf(stderr, "Failed to allocate client-side stream\n");
                return(-1);
            }
            stream_ctx->stream_id = stream_id;
            stream_ctx->stream_type = SERVER;
            if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
                fprintf(stderr, "Failed to set context for client-side stream\n");
                (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                return(-1);
            }
        }

        // Read and forward data directly
        if (stream_ctx->stream_type == SERVER) {
            printf("Server-side received %lu bytes\n", length);
            ret = picoquic_add_to_stream_with_ctx(global_proxy_ctx.client_cnx,
                                                  global_proxy_ctx.client_stream_id,
                                                  bytes, length, // Directly forward the bytes
                                                  fin_or_event == picoquic_callback_stream_fin,
                                                  (void *)stream_ctx);
        } else {
            printf("Client-side received %lu bytes\n", length);
            ret = picoquic_add_to_stream_with_ctx(global_proxy_ctx.server_cnx,
                                                  global_proxy_ctx.server_stream_id,
                                                  bytes, length, // Directly forward the bytes
                                                  fin_or_event == picoquic_callback_stream_fin,
                                                  (void *)stream_ctx);
        }
        if (ret != 0) {
            // Internal error
            (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
            return(-1);
        }
        break;

    case picoquic_callback_stream_reset:
    case picoquic_callback_stop_sending:
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stream_gap:
    case picoquic_callback_prepare_to_send:
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
    case picoquic_callback_datagram:
    case picoquic_callback_version_negotiation:
    case picoquic_callback_request_alpn_list:
    case picoquic_callback_set_alpn:
    case picoquic_callback_pacing_changed:
    case picoquic_callback_prepare_datagram:
    case picoquic_callback_datagram_acked:
    case picoquic_callback_datagram_lost:
    case picoquic_callback_datagram_spurious:
    case picoquic_callback_path_available:
    case picoquic_callback_path_suspended:
    case picoquic_callback_path_deleted:
    case picoquic_callback_path_quality_changed:
    case picoquic_callback_path_address_observed:
    case picoquic_callback_app_wakeup:
        // In future: receive and forward reset, stop_sending, close, possibly other events
        break;
    }
    return 0;
}

/*
 * Initialize a long-lived QUIC connection to the backend server.
 * Populate the connection with a single stream.
 *
 * In future: this could be done when the connection from the client is received.
 */
int sample_proxy_init(int server_port, const char* server_ip_text, picoquic_quic_t *quic) {
    int ret = 0;
    struct sockaddr_storage server_address;
    picoquic_cnx_t* cnx = NULL;
    uint64_t current_time = picoquic_current_time();
    char const* sni = PICOQUIC_SAMPLE_SNI;
    sample_proxy_stream_ctx_t* stream_ctx = NULL;
    int is_name = 0;
    printf("Setting up QUIC connection to %s:%d\n", server_ip_text, server_port);

    ret = picoquic_get_server_address(server_ip_text, server_port, &server_address, &is_name);
    if (ret != 0 || is_name) {
        fprintf(stderr, "Cannot get the IP address for <%s> port <%d>", server_ip_text, server_port);
        return -1;
    }

    // TODO confirm whether passing in the `quic` from the other side works??

    // Create connection
    cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
                             (struct sockaddr *)&server_address, current_time, 0, sni,
                             PICOQUIC_SAMPLE_ALPN, 1);
    if (cnx == NULL) {
        fprintf(stderr, "Could not create connection context to server\n");
        goto fail_cnx;
    }

    // Initialize callback
    picoquic_set_callback(cnx, sample_proxy_callback, &global_proxy_ctx);

    // Create stream
    stream_ctx = (sample_proxy_stream_ctx_t *)malloc(sizeof(sample_proxy_stream_ctx_t));
    if (stream_ctx == NULL) {
        fprintf(stderr, "Could not allocate memory for stream to server\n");
        goto fail_stream;
    }
    memset(stream_ctx, 0, sizeof(sample_proxy_stream_ctx_t));
    stream_ctx->stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    stream_ctx->stream_type = CLIENT;

    // Set stream active
    ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
    if (ret != 0) {
        fprintf(stdout, "Error %d, cannot initialize stream", ret);
        free(stream_ctx);
        goto fail_stream;
    }

    // Set global proxy data
    global_proxy_ctx.client_cnx = cnx;
    global_proxy_ctx.client_stream_id = stream_ctx->stream_id;
    return 0;

fail_stream:
    free(cnx);
fail_cnx:
    picoquic_free(quic);
    return -1;
}

/*
 * Proxy setup:
 * - Create QUIC contexts.
 * - Open connection to backend server.
 * - Invoke packet-processing loop.
 */
int picoquic_sample_proxy(int proxy_port, const char* proxy_cert, const char* proxy_key,
                          const char* cca, int server_port, const char *server_ip_text)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    uint64_t current_time = 0;

    printf("Starting Picoquic Sample proxy on port %d\n", proxy_port);
    printf("Proxying to %s:%d\n", server_ip_text, server_port);

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();

    /* Create QUIC context with callback */
    quic = picoquic_create(2, // Max connections this context can handle (one in each direction)
                           proxy_cert, proxy_key,
                           NULL, // no root cert
                           PICOQUIC_SAMPLE_ALPN, // no add'l protocol negotiation
                           sample_proxy_callback, // packet loop
                           NULL, // no default context
                           NULL, NULL, // no custom connection IDs
                           NULL, // no reset size
                           current_time,
                           NULL, // no simulated time
                           NULL, NULL, 0 // no ticket encryption
                           );

    if (quic == NULL) {
        fprintf(stderr, "Could not create quic context for accepting incoming connections\n");
        ret = -1;
    }
    else {
        picoquic_set_cookie_mode(quic, 2);
        picoquic_set_default_congestion_algorithm_by_name(quic, cca);
        // Avoid logging by default for performance
        // picoquic_set_qlog(quic, qlog_dir);
        picoquic_set_log_level(quic, 1);
        picoquic_set_key_log_file_from_env(quic);

        // Set up connection to backend server
        ret = sample_proxy_init(server_port, server_ip_text, quic);
    }

    if (ret == 0) {
        // Start packet loop
        ret = picoquic_packet_loop(quic, proxy_port, 0, 0, 0, 0, NULL, NULL);
    }

    /* And finish. */
    printf("Proxy exit, ret = %d\n", ret);

    /* Clean up */
    if (quic != NULL) {
        picoquic_free(quic);
        // TODO may need to free other structs?
    }

    return ret;
}
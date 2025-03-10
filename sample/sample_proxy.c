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
#include <pthread.h>
#include <assert.h>
#include <picoquic.h>
#include <picosocks.h>
#include <picoquic_utils.h>
#include <autoqlog.h>
#include "picoquic_sample.h"
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"

int sample_proxy_callback_to_server(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);
int sample_proxy_callback_to_client(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);
/*
 * Enable debug print statements.
 */
int DEBUG = 0;

/*
 * Args for thread functions.
 */
typedef struct st_sample_proxy_args_t {
    int proxy_port;
    picoquic_quic_t *quic;
} sample_proxy_args_t;

/*
 * The direction of the connection.
 */
typedef enum st_sample_conn_type_t {
    // Connection is between the proxy and the end-to-end connection's client
    TO_CLIENT,
    // Connection is between the proxy and the end-to-end connection's server
    TO_SERVER,
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

// For buffering data before marking stream as active
typedef struct st_sample_proxy_buf_t {
    void           *data;
    size_t          data_length;
    size_t          data_capacity;
    int             is_fin;
    pthread_mutex_t lock;
} sample_proxy_buf_t;

/*
 * Per-pair context, where a "pair" is a pair of QUIC connections
 * -- one "client-side" and one "server-side" -- that the proxy is
 * forwarding data between.
 * Each QUIC cconnection is limited to a single stream.
 */
typedef struct st_sample_proxy_ctx_t {
    // QUIC stream identifiers
    uint64_t        to_client_stream_id;
    uint64_t        to_server_stream_id;
    // Pointer to the QUIC connection structures,
    // usable for sending data
    picoquic_cnx_t *to_client_cnx;
    picoquic_cnx_t *to_server_cnx;
    // Stream context for the client connection
    sample_proxy_stream_ctx_t *to_client_stream_ctx;

    // Data for forwarding
    sample_proxy_buf_t to_client_buf;
} sample_proxy_ctx_t;

int INITIAL_CAPACITY = 10000;

int init_buf(sample_proxy_buf_t* buf) {
    if (pthread_mutex_init(&buf->lock, NULL) != 0) {
        printf("Mutex initialization failed\n");
        return -1;
    }
    buf->data = malloc(INITIAL_CAPACITY);
    if (buf->data == NULL) {
        printf("Failed to allocate memory for buffer\n");
        return -1;
    }
    buf->data_length = 0;
    buf->data_capacity = INITIAL_CAPACITY;
    buf->is_fin = 0;
    return 0;
}

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
    .to_client_stream_id = 0,
    .to_server_stream_id = 0,
    .to_client_cnx = NULL,
    .to_server_cnx = NULL,
};

void print_cnx_info(picoquic_cnx_t* cnx, uint64_t stream_id) {
    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr* peer_addr;
    memset(ip_str, 0, INET_ADDRSTRLEN);
    picoquic_get_peer_addr(cnx, &peer_addr);

    if (peer_addr->sa_family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in *)peer_addr;
        uint8_t* addr = (uint8_t *)&s4->sin_addr;
        printf("%d.%d.%d.%d:%d (stream ID: %lu)\n",
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
        if (global_proxy_ctx.to_client_cnx != NULL) {
            // Unknown new connection; warn of update
            fprintf(stderr, "Unknown new connection\n");
        }
        proxy_ctx = &global_proxy_ctx;
        global_proxy_ctx.to_client_cnx = cnx;
        picoquic_set_callback(cnx, sample_proxy_callback_to_client, proxy_ctx);
        picoquic_enable_keep_alive(cnx, 10000); // keep-alive at 1ms
        if (DEBUG) {
            printf("[DEBUG] New connection from: ");
            print_cnx_info(cnx, stream_id);
        }
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
            proxy_ctx->to_client_stream_id = stream_id;
            stream_ctx = (sample_proxy_stream_ctx_t*)malloc(sizeof(sample_proxy_stream_ctx_t));
            if (stream_ctx == NULL) {
                (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                fprintf(stderr, "Failed to allocate client-side stream\n");
                return(-1);
            }
            stream_ctx->stream_id = stream_id;
            stream_ctx->stream_type = TO_CLIENT;
            if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
                fprintf(stderr, "Failed to set context for client-side stream\n");
                (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                return(-1);
            }
            proxy_ctx->to_client_stream_ctx = stream_ctx;
            printf("Client stream initialized with ID %lu\n", stream_id);
        }

        // Read and forward data directly
        if (stream_ctx->stream_type == TO_SERVER) {
            if (global_proxy_ctx.to_client_buf.data_length + length >
                global_proxy_ctx.to_client_buf.data_capacity) {
                pthread_mutex_lock(&global_proxy_ctx.to_client_buf.lock);
                global_proxy_ctx.to_client_buf.data_capacity *= 2;
                if (DEBUG) {
                    printf("[DEBUG] Reallocating buffer to %lu bytes\n",
                           global_proxy_ctx.to_client_buf.data_capacity);
                }
                global_proxy_ctx.to_client_buf.data = realloc(global_proxy_ctx.to_client_buf.data, global_proxy_ctx.to_client_buf.data_capacity);
                pthread_mutex_unlock(&global_proxy_ctx.to_client_buf.lock);
            }
            pthread_mutex_lock(&global_proxy_ctx.to_client_buf.lock);
            memcpy(global_proxy_ctx.to_client_buf.data + global_proxy_ctx.to_client_buf.data_length, bytes, length);
            global_proxy_ctx.to_client_buf.data_length += length;
            if (fin_or_event == picoquic_callback_stream_fin) {
                global_proxy_ctx.to_client_buf.is_fin = 1;
            }
            // Data needs to be sent
            if (picoquic_mark_active_stream(global_proxy_ctx.to_client_cnx,
                                        global_proxy_ctx.to_client_stream_id, 1,
                                        global_proxy_ctx.to_client_stream_ctx) != 0) {
                fprintf(stderr, "Failed to mark client stream active\n");
            }
            pthread_mutex_unlock(&global_proxy_ctx.to_client_buf.lock);
            if (DEBUG && ret == 0) {
                printf("[DEBUG] Appended %lu bytes from server to client buffer (FIN: %s).\n", length,
                       fin_or_event == picoquic_callback_stream_fin ? "true" : "false");
                printf("[DEBUG] Received from: ");
                print_cnx_info(cnx, stream_id);
                printf("[DEBUG] Forwarded to: ");
                print_cnx_info(global_proxy_ctx.to_client_cnx, global_proxy_ctx.to_client_stream_id);
                printf("[DEBUG] Time: %lu\n", picoquic_current_time());
            }
        } else if (stream_ctx->stream_type == TO_CLIENT) {
            ret = picoquic_add_to_stream(global_proxy_ctx.to_server_cnx,
                                         global_proxy_ctx.to_server_stream_id,
                                         bytes, length, // Directly forward the bytes
                                         fin_or_event == picoquic_callback_stream_fin);
            if (DEBUG && ret == 0) {
                printf("[DEBUG] Forwarded %lu bytes from client to server (FIN: %s).\n", length,
                       fin_or_event == picoquic_callback_stream_fin ? "true" : "false");
                printf("[DEBUG] Received from: ");
                print_cnx_info(cnx, stream_id);
                printf("[DEBUG] Forwarded to: ");
                print_cnx_info(global_proxy_ctx.to_server_cnx, global_proxy_ctx.to_server_stream_id);
                printf("[DEBUG] Time: %lu\n", picoquic_current_time());
            }
        } else {
            assert(0);
        }
        if (ret != 0) {
            // Internal error
            printf("Error forwarding data: %d from: ", ret);
            print_cnx_info(cnx, stream_id);
            (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
            return(-1);
        }
        break;

    case picoquic_callback_almost_ready:
        printf("Connection almost ready for TX/RX: ");
        print_cnx_info(cnx, stream_id);
        if (DEBUG) {
            printf("[DEBUG] Time: %lu\n", picoquic_current_time());
        }
        break;
    case picoquic_callback_ready:
        printf("Connection ready for TX/RX: ");
        print_cnx_info(cnx, stream_id);
        if (DEBUG) {
            printf("[DEBUG] Time: %lu\n", picoquic_current_time());
        }
        break;
    case picoquic_callback_prepare_to_send:
        size_t   to_send = 0;
        uint8_t* buffer;
        int      is_fin = 0;
        if (DEBUG) {
            printf("[DEBUG] Connection ready for sending data: ");
            print_cnx_info(cnx, stream_id);
            printf("[DEBUG] Time: %lu\n", picoquic_current_time());
        }
        pthread_mutex_lock(&global_proxy_ctx.to_client_buf.lock);
        // Bytes to send
        to_send = global_proxy_ctx.to_client_buf.data_length;
        is_fin = global_proxy_ctx.to_client_buf.is_fin;
        if (to_send > length) {
            to_send = length;
            is_fin = 0;
        }

        buffer = picoquic_provide_stream_data_buffer(bytes, to_send, is_fin,
                                                     global_proxy_ctx.to_client_buf.data_length > to_send);
        if (buffer != NULL) {
            memcpy(buffer, global_proxy_ctx.to_client_buf.data, to_send);
        }
        if (DEBUG) {
            printf("[DEBUG] Sending %lu bytes to client (FIN: %s)\n", to_send, is_fin ? "true" : "false");
            printf("[DEBUG] Time: %lu\n", picoquic_current_time());
        }
        // Update data
        global_proxy_ctx.to_client_buf.data_length -= to_send;
        if (global_proxy_ctx.to_client_buf.data_length > 0) {
            memmove(global_proxy_ctx.to_client_buf.data, global_proxy_ctx.to_client_buf.data + to_send,
                    global_proxy_ctx.to_client_buf.data_length);
        }
        pthread_mutex_unlock(&global_proxy_ctx.to_client_buf.lock);
        break;
    case picoquic_callback_close:
    case picoquic_callback_application_close:
        printf("Connection closed: ");
        print_cnx_info(cnx, stream_id);
        if (stream_ctx != NULL) {
            free(stream_ctx);
        }
        if (DEBUG) {
            printf("[DEBUG] Time: %lu\n", picoquic_current_time());
        }
        break;
    case picoquic_callback_stream_reset:
    case picoquic_callback_stateless_reset:
    case picoquic_callback_stop_sending:
        printf("Stream reset or stop sending: ");
        print_cnx_info(cnx, stream_id);
        if (stream_ctx != NULL) {
            free(stream_ctx);
        }
        if (DEBUG) {
            printf("[DEBUG] Time: %lu\n", picoquic_current_time());
        }
        break;

    case picoquic_callback_stream_gap:
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
        printf("Received event %d on connection to %s\n",
               fin_or_event, stream_ctx->stream_type == TO_CLIENT ? "client" : "server");
        break;
    }
    return 0;
}


int sample_proxy_callback_to_server(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    sample_proxy_stream_ctx_t* stream_ctx = (sample_proxy_stream_ctx_t *)v_stream_ctx;
    int ret;
    assert(callback_ctx != NULL);
    if (fin_or_event == picoquic_callback_stream_fin || fin_or_event == picoquic_callback_stream_data) {
        if (stream_ctx == NULL) {
            // May need to repopulate stream context
            stream_ctx = (sample_proxy_stream_ctx_t *)malloc(sizeof(sample_proxy_stream_ctx_t));
            stream_ctx->stream_id = stream_id;
            stream_ctx->stream_type = TO_SERVER;
            ret = picoquic_set_app_stream_ctx(cnx, stream_ctx->stream_id, stream_ctx);
            if (ret != 0) {
                fprintf(stderr, "Error %d, cannot set stream context", ret);
                free(stream_ctx);
                return -1;
            }
            if (DEBUG) {
                printf("[DEBUG] New stream (id: %lu) from backend server\n", stream_id);
            }
        }
    }
    assert(global_proxy_ctx.to_server_cnx == cnx);
    assert(global_proxy_ctx.to_server_stream_id == stream_id);
    if (stream_ctx != NULL) {
        assert(stream_ctx->stream_type == TO_SERVER);
    }
    return sample_proxy_callback(cnx, stream_id, bytes, length, fin_or_event, callback_ctx, (void *)stream_ctx);
}

int sample_proxy_callback_to_client(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    sample_proxy_stream_ctx_t* stream_ctx = (sample_proxy_stream_ctx_t *)v_stream_ctx;
    assert(callback_ctx == NULL || global_proxy_ctx.to_client_cnx == cnx);
    assert(stream_ctx == NULL || global_proxy_ctx.to_client_stream_id == stream_id);
    if (stream_ctx != NULL) {
        assert(stream_ctx->stream_type == TO_CLIENT);
    }
    return sample_proxy_callback(cnx, stream_id, bytes, length, fin_or_event, callback_ctx, v_stream_ctx);
}

/*
 * Initialize a long-lived QUIC connection to the backend server.
 * Populate the connection with a single stream.
 *
 * In future: this could be done when the connection from the client is received.
 */
int sample_proxy_init_to_server(int server_port, const char* server_ip_text, const char* cca,
                                picoquic_quic_t **quic) {
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

    *quic = picoquic_create(1, NULL, NULL, NULL, PICOQUIC_SAMPLE_ALPN, NULL, NULL,
            NULL, NULL, NULL, current_time, NULL,
            NULL, NULL, 0);
    if (*quic == NULL) {
        fprintf(stderr, "Could not create quic context for backend server\n");
        return -1;
    }

    picoquic_set_default_congestion_algorithm_by_name(*quic, cca);
    picoquic_set_log_level(*quic, 1);

    // Create connection
    cnx = picoquic_create_cnx(*quic, picoquic_null_connection_id, picoquic_null_connection_id,
                             (struct sockaddr *)&server_address, current_time, 0, sni,
                             PICOQUIC_SAMPLE_ALPN, 1);
    if (cnx == NULL) {
        fprintf(stderr, "Could not create connection context to server\n");
        return -1;
    }

    // Initialize callback
    picoquic_set_callback(cnx, sample_proxy_callback_to_server, &global_proxy_ctx);
    ret = picoquic_start_client_cnx(cnx);
    if (ret < 0) {
        fprintf(stderr, "Could not activate connection to backend server\n");
        free(cnx);
        return -1;
    }

    printf("Connection to backend server established; initial connection ID: ");
    picoquic_connection_id_t icid = picoquic_get_initial_cnxid(cnx);
    for (uint8_t i = 0; i < icid.id_len; i++) {
        printf("%02x", icid.id[i]);
    }
    printf("\n");

    // Create stream
    stream_ctx = (sample_proxy_stream_ctx_t *)malloc(sizeof(sample_proxy_stream_ctx_t));
    if (stream_ctx == NULL) {
        fprintf(stderr, "Could not allocate memory for stream to server\n");
        free(cnx);
        return -1;
    }
    memset(stream_ctx, 0, sizeof(sample_proxy_stream_ctx_t));
    stream_ctx->stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    stream_ctx->stream_type = TO_SERVER;

    // Set stream active
    ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
    if (ret != 0) {
        fprintf(stderr, "Error %d, cannot initialize stream", ret);
        free(stream_ctx);
        free(cnx);
        return -1;
    }
    printf("Stream to backend server initialized with ID %lu\n", stream_ctx->stream_id);

    // Set global proxy data
    global_proxy_ctx.to_server_cnx = cnx;
    global_proxy_ctx.to_server_stream_id = stream_ctx->stream_id;
    // Enable keep-alives at 10ms
    // The connections aren't waking up to send data unless they receive data.
    // We can force them to wake up by sending a keep-alive.
    picoquic_enable_keep_alive(cnx, 10000);
    return 0;
}

// Thread function for opening port to accept client connections
void* to_client_func(void *args) {
    sample_proxy_args_t *proxy_args = (sample_proxy_args_t *)args;
    printf("Start packet loop to listen for connections from client on %d\n", proxy_args->proxy_port);
    picoquic_packet_loop(proxy_args->quic, proxy_args->proxy_port, AF_INET, 0, 0, 0, NULL, NULL);
    return NULL;
}

// Thread function for maintaining connection to backend server
void* to_server_func(void *args) {
    sample_proxy_args_t *proxy_args = (sample_proxy_args_t *)args;
    printf("Start packet loop to backend server\n");
    picoquic_packet_loop(proxy_args->quic, 0, AF_INET, 0, 0, 0, NULL, NULL);
    return NULL;
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
    int ret = 0;
    picoquic_quic_t* quic_to_client = NULL;
    picoquic_quic_t* quic_to_server = NULL;
    uint64_t current_time = 0;
    pthread_t to_client_thread, to_server_thread;
    sample_proxy_args_t to_client_args;
    sample_proxy_args_t to_server_args;

    printf("Starting Picoquic Sample proxy on port %d\n", proxy_port);
    printf("Proxying to %s:%d\n", server_ip_text, server_port);

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();

    ret = init_buf(&global_proxy_ctx.to_client_buf);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize buffer for client stream\n");
        return ret;
    }

    /* Create QUIC context with callback */
    quic_to_client = picoquic_create(1, // Max connections this context can handle (one in each direction)
                                     proxy_cert, proxy_key,
                                     NULL, // no root cert
                                     PICOQUIC_SAMPLE_ALPN, // no add'l protocol negotiation
                                     sample_proxy_callback_to_client, // packet loop
                                     NULL, // no default context
                                     NULL, NULL, // no custom connection IDs
                                     NULL, // no reset size
                                     current_time,
                                     NULL, // no simulated time
                                     NULL, NULL, 0 // no ticket encryption
                                     );

    if (quic_to_client == NULL) {
        fprintf(stderr, "Could not create quic context for accepting incoming connections\n");
        ret = -1;
    }
    else {
        picoquic_set_cookie_mode(quic_to_client, 2);
        picoquic_set_default_congestion_algorithm_by_name(quic_to_client, cca);
        // Avoid logging by default for performance
        // picoquic_set_qlog(quic, qlog_dir);
        picoquic_set_log_level(quic_to_client, 1);
        picoquic_set_key_log_file_from_env(quic_to_client);

        // Set up connection to backend server
        ret = sample_proxy_init_to_server(server_port, server_ip_text, cca, &quic_to_server);
    }


    // Start packet loops
    if (ret == 0) {
        to_server_args.proxy_port = proxy_port;
        to_server_args.quic = quic_to_server;
        pthread_create(&to_server_thread, NULL, to_server_func, (void *)&to_server_args);
        to_client_args.proxy_port = proxy_port;
        to_client_args.quic = quic_to_client;
        pthread_create(&to_client_thread, NULL, to_client_func, (void *)&to_client_args);
    }

    pthread_join(to_client_thread, NULL);
    pthread_join(to_server_thread, NULL);

    /* And finish. */
    printf("Proxy exit, ret = %d\n", ret);

    /* Clean up */
    if (quic_to_client != NULL) {
        picoquic_free(quic_to_client);
    }
    if (quic_to_server != NULL) {
        picoquic_free(quic_to_server);
    }
    pthread_mutex_destroy(&global_proxy_ctx.to_client_buf.lock);
    return ret;
}
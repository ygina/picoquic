/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef QUICPERF_H
#define QUICPERF_H

#define QUICPERF_ALPN "perf"
#define QUICPERF_ALPN_LEN 4

#define QUICPERF_NO_ERROR 0
#define QUICPERF_ERROR_NOT_IMPLEMENTED 1
#define QUICPERF_ERROR_INTERNAL_ERROR 2
#define QUICPERF_ERROR_NOT_ENOUGH_DATA_SENT 3
#define QUICPERF_ERROR_TOO_MUCH_DATA_SENT 4

#define QUICPERF_STREAM_ID_INITIAL UINT64_MAX

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    quicperf_media_batch = 0,
    quicperf_media_stream,
    quicperf_media_datagram,
} quicperf_media_type_enum;

typedef struct st_quicperf_stream_desc_t {
    char id[16];
    char previous_id[16];
    uint64_t repeat_count;
    quicperf_media_type_enum media_type;
    uint8_t frequency;
    uint64_t post_size;
    uint64_t response_size; /* If infinite, client will ask stop sending at this size */
    uint64_t nb_frames;
    uint64_t frame_size;
    uint64_t group_size;
    uint64_t first_frame_size;
    uint64_t reset_delay;
    uint8_t priority;
    int is_infinite; /* Set if the response size was set to "-xxx" */
    int is_client_media;
} quicperf_stream_desc_t;

typedef struct st_quicperf_media_command_t {
    uint64_t media_stream_id;
    uint8_t priority;
    uint64_t media_type;
    uint64_t frequency;
    uint64_t number_of_frames;
    uint64_t frame_size;
    uint64_t frames_per_group;
    uint64_t first_frame_size;
} quicperf_media_command_t;

typedef struct st_quicperf_media_report_t {
    uint64_t media_stream_id;
    uint64_t group_id;
    uint64_t frame_id;
    uint64_t client_time_stamp;
    uint64_t server_time_stamp;
} quicperf_media_report_t;

typedef struct st_quicperf_stream_ctx {
    picosplay_node_t quicperf_stream_node;
    /* Stream identification by ID is only used by the client */
    uint64_t stream_desc_index;
    uint64_t stream_id;
    uint64_t rep_number;
    uint64_t group_id;

    uint8_t length_header[8];
    /* Variables used for batch streams*/
    uint64_t post_size; /* Unknown on server, from scenario on client */
    uint64_t nb_post_bytes;  /* Sent on client, received on server */
    uint64_t response_size; /* From data on server, from scenario on client */
    uint64_t nb_response_bytes; /* Received on client, sent on server */
    uint64_t post_time; /* Time stream open (client) or first byte received (server) */
    uint64_t post_fin_time; /* Time last byte sent (client) or received (server) */
    uint64_t response_time; /* Time first byte sent (server) or received (client) */
    uint64_t response_fin_time; /* Time last byte sent (server) or received (client) */

    /* Variables used for media streams*/
    uint64_t start_time;
    uint64_t next_frame_time;
    uint64_t nb_frames; /* number of frames required */
    uint64_t nb_frames_sent;
    uint64_t frame_size;
    uint64_t first_frame_size;
    uint64_t frame_bytes_sent;

    uint8_t priority;
    uint8_t frequency;
    /* Variables for receiving media */
    uint64_t nb_frames_received;
    uint64_t frames_bytes_received;
    uint64_t frame_start_stamp;
    /* Flags */
    unsigned int is_media : 1;
    unsigned int is_datagram : 1;
    unsigned int is_activated : 1;
    unsigned int stop_for_fin : 1;
    unsigned int is_stopped : 1;
    unsigned int is_closed : 1;
} quicperf_stream_ctx_t;

typedef struct st_quicperf_ctx_t {
    int is_client;
    int progress_observed;
    size_t nb_scenarios;
    size_t nb_open_streams;
    uint64_t last_interaction_time;
    quicperf_stream_desc_t* scenarios;
    picosplay_tree_t quicperf_stream_tree;
    /* Buffer for handling the command or response. */
    uint8_t command_length; /* 0 if not received yet. */
    uint8_t bytes_received;
    uint8_t command_bytes[64];
    /* Management of wakeup time */
    uint64_t stream_wakeup_time;
    /* To do: management of datagrams */
    uint64_t datagram_wakeup_time;
    size_t datagram_size;
    uint8_t datagram_priority;
    int nb_datagrams;
    int datagram_is_activated;
    /* Reporting file if available */
    FILE* report_file;
    /* Statistics gathered on client */
    uint64_t data_sent;
    uint64_t data_received;
    uint64_t nb_streams;
} quicperf_ctx_t;

quicperf_ctx_t* quicperf_create_ctx(const char* scenario_text);
void quicperf_delete_ctx(quicperf_ctx_t* ctx);

int quicperf_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

size_t quicperf_parse_media_command(const uint8_t* data, size_t length, quicperf_media_command_t* cmd);
size_t quicperf_format_media_command(uint8_t* data, size_t length, const quicperf_media_command_t* cmd);
size_t quicperf_parse_media_report(const uint8_t* data, size_t length, quicperf_media_report_t* rpt);
size_t quicperf_format_media_report(uint8_t* data, size_t length, const quicperf_media_report_t* rpt);
size_t quicperf_accumulate_buffer(uint8_t* data, size_t length, uint8_t* msg_length, uint8_t* bytes_received, uint8_t* buffer, size_t buffer_length);

#ifdef __cplusplus
}
#endif

#endif /* QUICPERF_H */

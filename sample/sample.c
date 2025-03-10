/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

/* The "sample" project builds a simple file transfer program that can be
 * instantiated in client or server mode. The programe can be instantiated
 * as either:
 *    picoquic_sample client server_name port folder *queried_file
 * or:
 *    picoquic_sample server port cert_file private_key_file folder
 *
 * The client opens a quic connection to the server, and then fetches
 * the listed files. The client opens one bidir client stream for each
 * file, writes the requested file name in the stream data, and then
 * marks the stream as finished. The server reads the file name, and
 * if the named file is present in the server's folder, sends the file
 * content on the same stream, marking the fin of the stream when all
 * bytes are sent. If the file is not available, the server resets the
 * stream. If the client receives the file, it writes its content in the
 * client's folder.
 *
 * Server or client close the connection if it remains inactive for
 * more than 10 seconds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <picosocks.h>
#include "picoquic_sample.h"

static void usage(char const * sample_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s client server_name port folder cca sidekick_ack_delay [threshold freq_pkts freq_ms target_addr]? *queried_file\n", sample_name);
    fprintf(stderr, "    %s background server_name port folder\n", sample_name);
    fprintf(stderr, "or :\n");
    fprintf(stderr, "    %s server port cert_file private_key_file folder nbytes cca\n", sample_name);
    exit(1);
}

int get_port(char const* sample_name, char const* port_arg)
{
    int server_port = atoi(port_arg);
    if (server_port <= 0) {
        fprintf(stderr, "Invalid port: %s\n", port_arg);
        usage(sample_name);
    }

    return server_port;
}

int get_nbytes(char const *sample_name, char const *nbytes_arg)
{
    int nbytes = atoi(nbytes_arg);
    if (nbytes <= 0) {
        fprintf(stderr, "Invalid number of bytes: %s\n", nbytes_arg);
        usage(sample_name);
    }
    return nbytes;
}

int main(int argc, char** argv)
{
    int exit_code = 0;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    if (argc < 2) {
        usage(argv[0]);
    }
    else if (strcmp(argv[1], "client") == 0) {
        if (argc != 8 && argc != 12) {
            usage(argv[0]);
        }
        else {
            int server_port = get_port(argv[0], argv[3]);
            int nb_files = 1;
            char const** file_names = (char const **)(argv + argc - nb_files);
            int sidekick_ack_delay = atoi(argv[6]);

            if (argc == 8) {
                picoquic_sample_client(argv[2], argv[5], server_port, argv[4], nb_files, file_names, sidekick_ack_delay,
                    false, 0, 0, 0, "");
            } else {
                int threshold = atoi(argv[7]);
                int freq_pkts = atoi(argv[8]);
                int freq_ms = atoi(argv[9]);
                char* target_addr = argv[10];
                picoquic_sample_client(argv[2], argv[5], server_port, argv[4], nb_files, file_names, sidekick_ack_delay,
                    true, threshold, freq_pkts, freq_ms, target_addr);
            }
        }
    }
    else if (strcmp(argv[1], "background") == 0) {
        if (argc != 5) {
            usage(argv[0]);
        }
        else {
            int server_port = get_port(argv[0], argv[3]);

            exit_code = picoquic_sample_background(argv[2], server_port, argv[4]);
        }
    }
    else if (strcmp(argv[1], "server") == 0) {
        if (argc != 8) {
            usage(argv[0]);
        }
        else {
            int server_port = get_port(argv[0], argv[2]);
            int nbytes = get_nbytes(argv[0], argv[6]);
            exit_code = picoquic_sample_server(server_port, nbytes, argv[7], argv[3], argv[4], argv[5]);
        }
    }
    else
    {
        usage(argv[0]);
    }

    exit(exit_code);
}
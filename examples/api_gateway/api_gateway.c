/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2021 George Washington University
 *            2015-2021 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * api_gateway.c - A gateway NF to support containerized network functions.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>

#include "api_gateway.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "scaler.h"

#define NF_TAG "api_gateway"

// Container's index
int cont_index = 0; 

/* Print a usage message. */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
}

/* Parse the application arguments. */
static int
parse_app_args(int argc, char *argv[], const char *progname, struct state_info *stats) {
        int c;

        // default max containers
        max_containers = MAX_CONTAINERS;

        while ((c = getopt(argc, argv, "p:n:k")) != -1) {
                switch (c) {
                        case 'p':
                                stats->print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case 'n':
                                max_containers = strtoul(optarg, NULL, 10);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }
        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called.
 */
static void
print_stats(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        uint64_t total_packets = 0;

        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = (struct state_info *)nf->data;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("\nStatistics ====================================");
        int i;
        for (i = 0; i < stats->max_containers; i++) {
                printf(
                    "\nStatistics for NF Container %d ------------------------------"
                    "\nPackets forwarded to: %20" PRIu64,
                    i, stats->statistics[i]);

                total_packets += stats->statistics[i];
        }
        printf(
            "\nAggregate statistics ==============================="
            "\nTotal packets forwarded: %17" PRIu64 "\nPackets dropped: %18" PRIu64,
            total_packets, stats->packets_dropped);
        printf("\n====================================================\n");

        printf("\n\n");
}

/*
 * This function prints the statistics during run time. 
 * Displaying:
 * 1) Number of containers
 */
static void 
stats_display(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        // const char clr[] = {27, '[', '2', 'J', '\0'};
        // const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        uint64_t total_packets = 0;

        /* Clear screen and move to top left */
        // printf("%s%s", clr, topLeft);

        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = (struct state_info *)nf->data;

        // Printing total & indivdual containers
        printf("\nTotal Running Containers: %d", rte_atomic16_read(&num_running_containers));
        for (int i = 0; i < rte_atomic16_read(&num_running_containers); i++) {
                printf(
                    "\nStatistics for NF Container %d ------------------------------"
                    "\nPackets forwarded to: %20" PRIu64,
                    i, stats->statistics[i]);

                total_packets += stats->statistics[i];
        }
        printf("\nTotal Packets: %17" PRIu64, total_packets);
}

/*
 * This function performs an IPV4 lookup int the hash table. Packets are then forwared to the corresponding NF.
 */
static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;

        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = (struct state_info *)nf->data;

        // stats->print_delay = 1,000,000
        if (counter++ == stats->print_delay) {
                print_stats(nf_local_ctx);
                counter = 0;
        }

        struct data *data;
        data = get_ipv4_dst(pkt);
        if (!data) {
                // probably not an IPV4 packet
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        } else if (data->dest > 0) {
                // printf("Container RX: %d and TX: %d\n", data->dest, data->poll_fd);
                // printf("data->dest: %d\n", data->dest);
                write_packet(data->dest, pkt);
                if (data->cont_idx == -1) {
                        data->cont_idx = cont_index;
                        cont_index++;
                }
                stats->statistics[data->cont_idx] = ++data->pkts;
                stats_display(nf_local_ctx);
        } else {
                if (data->num_buffered < 2) {
                        rte_rwlock_write_lock(&data->lock);
                        data->buffer[data->num_buffered] = pkt;
                        data->num_buffered++;
                        rte_rwlock_write_unlock(&data->lock);
                        data->pkts++;
                } else {
                        meta->action = ONVM_NF_ACTION_DROP;
                        return 0;
                }
        }

        meta->destination = data->dest;
        stats->statistics[data->dest]++;
        meta->action = ONVM_NF_ACTION_TONF;
        return 0;
}

struct onvm_nf_local_ctx *
start_child(const char *tag) {
        struct onvm_nf_local_ctx *child_local_ctx;
        struct onvm_nf_init_cfg *child_init_cfg;
        child_init_cfg = onvm_nflib_init_nf_init_cfg(tag);

        /* Prepare init data for the child */
        // make service ID something to denote we are not taking packets
        child_init_cfg->service_id = 5;

        child_local_ctx = onvm_nflib_init_nf_local_ctx();

        if (onvm_nflib_start_nf(child_local_ctx, child_init_cfg) < 0) {
                printf("Failed to spawn child NF\n");
                return NULL;
        }

        child_local_ctx->nf->thread_info.parent = api_gateway_id;

        return child_local_ctx;
}

void *
start_scaler(void *arg __attribute__((unused))) {
        struct onvm_nf_local_ctx *ctx = start_child("scaler");
        if (!ctx) {
                // failed
                return NULL;
        }

        scaler();
        onvm_nflib_stop(ctx);
        return NULL;
}

void *
start_polling(void *arg __attribute__((unused))) {
        struct onvm_nf_local_ctx *ctx = start_child("polling");
        if (!ctx) {
                // failed
                return NULL;
        }

        polling();
        onvm_nflib_stop(ctx);
        return NULL;
}

void
nf_setup(struct onvm_nf_local_ctx *nf_local_ctx) {
        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = (struct state_info *)nf->data;
        api_gateway_id = nf->instance_id;
        if (setup_hash() < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_free(stats);
                rte_exit(EXIT_FAILURE, "Unable to setup Hash\n");
        }

        if (setup_buffer_map() < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_free(stats);
                rte_exit(EXIT_FAILURE, "Unable to setup buffer map\n");
        }

        printf("Hash table successfully created. \n");

        init_rings();

        pthread_t scale_thd;
        // scaler acts as container initializer and garbage collector
        pthread_create(&scale_thd, NULL, start_scaler, NULL);

        pthread_t poll_thd;
        // polling acts as tx thread that gets all container packets out through network
        pthread_create(&poll_thd, NULL, start_polling, NULL);

        // tell manager we need children to clean up before exiting
        rte_atomic16_set(&nf->thread_info.children_cnt, 2);

        RTE_LOG(INFO, APP, "Spawned scaler and poll child NFs\n");

        // set up polling mbuf buffer
        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if (pktmbuf_pool == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }
}

void
sig_handler(int sig) {
        if (sig != SIGINT && sig != SIGTERM)
                return;

        /* Will stop the processing for all spawned threads in advanced rings mode */
        worker_keep_running = 0;
}

void
init_rings(void) {
        const unsigned ring_size = 64;

        container_init_ring = rte_ring_create(_INIT_CONT_TRACKER, ring_size, rte_socket_id(), RING_F_SP_ENQ);
        if (container_init_ring == NULL)
                rte_exit(EXIT_FAILURE, "Problem getting receiving ring\n");
        scale_buffer_ring = rte_ring_create(_SCALE_2_BUFFER, NF_QUEUE_RINGSIZE, rte_socket_id(), RING_F_SP_ENQ);
        if (scale_buffer_ring == NULL)
                rte_exit(EXIT_FAILURE, "Problem getting buffer ring for scaling.\n");
}

int
main(int argc, char *argv[]) {
        int arg_offset;
        struct onvm_nf_function_table *nf_function_table;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();

        // set up signals for the threads to exit
        worker_keep_running = 1;
        onvm_nflib_start_signal_handler(nf_local_ctx, sig_handler);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
        nf_function_table->setup = &nf_setup;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                onvm_ft_free(em_tbl);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        argc -= arg_offset;
        argv += arg_offset;

        /* Allocate NF data structure to keep track of state information. */
        struct onvm_nf *nf = nf_local_ctx->nf;
        struct state_info *stats = rte_calloc("state", 1, sizeof(struct state_info), 0);
        if (stats == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                onvm_ft_free(em_tbl);
                rte_exit(EXIT_FAILURE, "Unable to initialize NF stats.");
        }
        nf->data = (void *)stats;

        /* Set defualt print delay */
        stats->print_delay = 1000000;

        /* Parse application arguments. */
        if (parse_app_args(argc, argv, progname, stats) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                onvm_ft_free(em_tbl);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        onvm_nflib_run(nf_local_ctx);

        // should be exiting now
        worker_keep_running = 0;
        onvm_nflib_stop(nf_local_ctx);

        /* Stats will be freed by manager. Do not put table data structures in the stats struct as doing so will result
           in seg fault. Update stats to be deallocated by NF? */
        onvm_ft_free(em_tbl);
        rte_memzone_free(mz_cont_nf);

        // clean up rings
        rte_ring_free(container_init_ring);
        rte_ring_free(scale_buffer_ring);

        printf("If we reach here, program is ending\n");
        return 0;
}

/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2020 George Washington University
 *            2015-2020 University of California Riverside
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
 * api_gateway.h - This application performs L3 forwarding.
 ********************************************************************/

#include "onvm_flow_table.h"
#include "onvm_pkt_common.h"

#define NUM_CONTAINERS 4
#define CONT_NF_RXQ_NAME "Cont_Client_%u_RX"
#define CONT_NF_TXQ_NAME "Cont_Client_%u_TX"
#define CONT_RX_PIPE_NAME "/tmp/rx/%d"
#define CONT_TX_PIPE_NAME "/tmp/tx/%d"
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"

/* This defines the maximum possible number entries in out flow table. */
#define HASH_ENTRIES 100  /// TODO: Possibly move this over to state struct.

/* Handle signals and shutdowns between threads */
rte_atomic16_t signal_exit_flag;

struct onvm_ft *em_tbl;

struct container_nf *cont_nfs;

const struct rte_memzone *mz_cont_nf;

struct rte_mempool *pktmbuf_pool;

static const char *_GATE_2_SCALE = "GATEWAY_2_SCALER";
static const char *_SCALE_2_GATE = "SCALER_2_GATEWAY";
static const char *_SCALE_BUFFER = "SCALING_BUFFER";
struct rte_ring *to_scale_ring, *to_gate_ring, *scale_buffer_ring;
struct packet_buf *scaling_buf;

struct onvm_nf_local_ctx *nf_local_ctx;

/*Struct that holds all NF state information */
struct state_info {
        uint64_t statistics[NUM_CONTAINERS];
        uint64_t dest_eth_addr[NUM_CONTAINERS];
        uint64_t packets_dropped;
        uint32_t print_delay;
        uint8_t print_keys;
        uint8_t max_containers;
};

struct container_nf {
        struct rte_ring *rx_q;
        struct rte_ring *tx_q;
        uint16_t instance_id;
        uint16_t service_id;
};

/* Packet struct that exists on the container */
typedef struct pkt {
        void *buf_addr;
        uint16_t refcnt;
        uint16_t nb_segs;
        uint16_t port;
        uint64_t ol_flags;
        uint32_t pkt_len;
        uint16_t data_len;
        uint16_t vlan_tci;
        uint16_t vlan_tci_outer;
        uint16_t buf_len;
        uint16_t priv_size;
        uint16_t timesync;
        uint16_t dynfield1[9];
        uint32_t packet_type;
        uint8_t l2_type : 4;
        uint8_t l3_type : 4;
        uint8_t l4_type : 4;
        uint8_t tun_type : 4;
        uint8_t inner_esp_next_proto;
        uint8_t inner_l2_type : 4;
        uint8_t inner_l3_type : 4;
        uint8_t inner_l4_type : 4;
} pkt;

/* Function pointers for LPM or EM functionality. */

int
setup_hash(struct state_info *stats);

uint16_t
get_ipv4_dst(struct rte_mbuf *pkt);

void
init_cont_nf(struct state_info *stats);

void *
buffer(void *in);

void *
polling(void *in);

void
init_rings(void);

void
sig_handler(int sig);
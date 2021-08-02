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

#include <rte_lpm.h>
#include <rte_rwlock.h>

#include "onvm_common.h"
#include "onvm_flow_table.h"
#include "onvm_pkt_common.h"

#define NUM_CONTAINERS 10
#define PIPE_DIR "/tmp/pipe"
#define CONT_PIPE_DIR_NAME "/tmp/pipe/%d"
#define CONT_RX_PIPE_NAME "/tmp/pipe/%d/rx"
#define CONT_TX_PIPE_NAME "/tmp/pipe/%d/tx"
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define FLOW_RING_NAME "IPv4_Flow_%u_%d"
#define _SCALE_2_BUFFER "SCALE_2_BUFFER"
#define _INIT_CONT_TRACKER "INIT_CONT_TRACKER"
#define COMMENT_LEAD_CHAR ('#')

// 1024 maximum open file descriptors (stated by linux) / (2 pipes/container)
#define MAX_CONTAINERS 512

/* This defines the maximum possible number entries in out flow table. */
#define HASH_ENTRIES 100  /// TODO: Possibly move this over to state struct.

// How many milliseconds should we set for epoll_wait in the polling thread
#define POLLING_TIMEOUT 500

// Maximum number of packets buffered in a ring for each flow
#define MAX_FLOW_PACKETS 4096

int max_containers;

uint16_t api_gateway_id;

/* Handle signals and shutdowns between threads */
uint8_t worker_keep_running;

/* Handle mapping of IP flow to container pipe fds */
struct onvm_ft *em_tbl;
/* Handle mapping of IP flow to linked_list of buffered packets */
struct onvm_ft *buffer_map;

const struct rte_memzone *mz_cont_nf;

struct rte_mempool *pktmbuf_pool;

struct queue_mgr *poll_tx_mgr;

/* communicate how many containers with flows set between the threads */
rte_atomic16_t num_running_containers;

// buffer pulls from gateway and scaler ring buffers

struct rte_ring *scale_buffer_ring, *container_init_ring;
struct packet_buf *scaling_buf, *pkts_deq_burst, *pkts_enq_burst;

struct onvm_nf_local_ctx *nf_local_ctx;

/* tuple of pipe file descriptors */
struct pipe_fds {
        int tx_pipe;
        int rx_pipe;
};

/*Struct that holds all NF state information */
struct state_info {
        uint64_t statistics[NUM_CONTAINERS];
        uint64_t dest_eth_addr[NUM_CONTAINERS];
        uint64_t packets_dropped;
        uint32_t print_delay;
        uint8_t max_containers;
};

void
nf_setup(struct onvm_nf_local_ctx *nf_local_ctx);

/* functions to start up threads as child NFs */
struct onvm_nf_local_ctx *
start_child(const char *tag);

void *
start_scaler(void *arg);

void
scaler(void);

void *
start_polling(void *arg);

void
polling(void);

// Helpers
void
init_rings(void);

void
sig_handler(int sig);

struct queue_mgr *
create_tx_poll_mgr(void);

void
enqueue_mbuf(struct rte_mbuf *pkt);

int
add_fd_epoll(int fd);

int
rm_fd_epoll(int fd);

// Pipe read/write helpers
int
read_packet(int fd, struct rte_mbuf *);

int
write_packet(int fd, struct rte_mbuf *packet);

// Flow table helper

/*
 * This struct extends the onvm_ft struct to support longest-prefix match.
 * The depth or length of the rule is the number of bits of the rule that is stored in a specific entry.
 * Range is from 1-32.
 */
struct onvm_parser_ipv4_5tuple {
        struct onvm_ft_ipv4_5tuple key;
        uint32_t src_addr_depth;
        uint32_t dst_addr_depth;
};
/* Struct that holds info about each flow, and is stored at each flow table entry.
    Dest stores the destination NF or action to take.
 */
struct data {
        uint8_t dest;
        uint8_t poll_fd;
        struct rte_mbuf *buffer[2];
        uint8_t num_buffered;
        rte_rwlock_t lock;
        int cont_idx;
        int pkts;
};

enum {
        CB_FLD_SRC_ADDR,
        CB_FLD_DST_ADDR,
        CB_FLD_SRC_PORT_DLM,
        CB_FLD_SRC_PORT,
        CB_FLD_DST_PORT,
        CB_FLD_DST_PORT_DLM,
        CB_FLD_PROTO,
        CB_FLD_DEST,
        CB_FLD_NUM,
};

enum {
        ONVM_TABLE_EM,
        ONVM_TABLE_LPM,
};

/* Function pointers for LPM or EM functionality. */

int
setup_hash(void);

struct data *
get_ipv4_dst(struct rte_mbuf *pkt);

int
get_cb_field(char **in, uint32_t *fd, int base, unsigned long lim, char dlm);

int
parse_ipv4_net(char *in, uint32_t *addr, uint32_t *depth);

/* This function fills the key and return the destination or action to be stored in the table entry.*/
int
parse_ipv4_5tuple_rule(char *str, struct onvm_parser_ipv4_5tuple *ipv4_tuple);

/* Bypass comment and empty lines */
int
is_bypass_line(char *buff);

/*
 * This function takes in a file name and parses the file contents to
 * add custom flows to the the flow table passed in. Currently
 * hash and lpm is supported.
 */
int
add_rules(void *tbl, const char *rule_path, int table_type);

int
setup_buffer_map(void);

int
add_buffer_map(struct rte_mbuf *pkt);

struct rte_ring *
new_ring_buffer_map(struct onvm_ft_ipv4_5tuple key);

struct rte_ring *
get_buffer_flow(struct onvm_ft_ipv4_5tuple key);

const char *
get_flow_queue_name(struct onvm_ft_ipv4_5tuple key);

int32_t
dequeue_and_free_buffer_map(struct onvm_ft_ipv4_5tuple *key, int tx_fd, int rx_fd);

void
print_key(struct rte_mbuf *);
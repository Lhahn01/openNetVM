#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_common.h"
#include "onvm_pkt_helper.h"

#include "api_gateway.h"

int epoll_fd = -1;

/* Turn a container packet into a dpdk rte_mbuf pkt */
void
enqueue_mbuf(struct rte_mbuf *pkt) {
        // find which port to send packet to
        struct data *data;
        if (true) {
                return;
        }
        printf("testing\n");
        data = get_ipv4_dst(pkt);
        if (data->dest == 0) {
                // TODO: figure out if this is a malicious scenario
                perror("Red flag: container sent packet we couldn't handle\n");
                return;
        }

        // enqueue pkt directly (instead of normal NF tx ring)
        onvm_pkt_enqueue_port(poll_tx_mgr, data->dest, pkt);
}

/*
 * Create a queue_mgr (replacing manager TX thread)
 * see onvm/onvm_mgr/main.c for example creating queue_mgr
 */
struct queue_mgr *
create_tx_poll_mgr(void) {
        struct queue_mgr *poll_mgr = rte_calloc(NULL, 1, sizeof(struct queue_mgr), RTE_CACHE_LINE_SIZE);
        if (poll_mgr == NULL) {
                return NULL;
        }
        poll_mgr->mgr_type_t = MGR;
        poll_mgr->id = 0;
        poll_mgr->tx_thread_info = NULL;
        poll_mgr->nf_rx_bufs = NULL;
        return poll_mgr;
}

/* thread to continuously poll all tx_fds from containers for packets to send out to network */
void
polling(void) {
        struct rte_mbuf pkt;
        int i;

        // epoll specific initializers
        int event_count;
        struct epoll_event events[max_containers];

        // initialize epoll file descriptor for polling
        epoll_fd = epoll_create1(0);

        for (; worker_keep_running;) {
                // blocking wait on epoll for the file descriptors
                event_count = epoll_wait(epoll_fd, events, rte_atomic16_read(&num_running_containers), POLLING_TIMEOUT);
                for (i = 0; i < event_count; i++) {
                        // TODO: implement fairness for polling pipes
                        // read the container pipe buffer until its empty
                        // printf("\n[Received] Container TX fd %d\n", events[i].data.fd);
                        while ((read_packet(events[i].data.fd, &pkt)) != -1) {
                                // enqueue rte_mbuf onto DPDK port
                                enqueue_mbuf(&pkt);
                                print_key(&pkt);
                        }
                }
        }

        if (close(epoll_fd)) {
                perror("Couldn't close epoll file descriptor\n");
                return;
        }

        printf("Polling thread exiting\n");
}

/* Helpers to manipulate epoll list */
int
add_fd_epoll(int fd) {
        if (fd < 0 || epoll_fd < 0) {
                // bad input
                return -1;
        }

        struct epoll_event *event = (struct epoll_event *)(malloc(sizeof(struct epoll_event)));
        event->events = EPOLLIN;
        // set fd of where to poll from
        event->data.fd = fd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, event) != 0) {
                return -1;
        }

        // success, new container should be polled
        rte_atomic16_inc(&num_running_containers);
        return 0;
}

int
rm_fd_epoll(int fd) {
        if (fd < 0 || epoll_fd < 0) {
                // bad input
                return -1;
        }

        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) != 0) {
                return -1;
        }

        // successfullly removed container from epoll list - no need to track anymore
        rte_atomic16_dec(&num_running_containers);
        return 0;
}

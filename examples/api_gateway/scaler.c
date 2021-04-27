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
 * scaler.c - A container auto-scaling API for gateway to communicate with.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_mbuf.h>

#include "api_gateway.h"
#include "scaler.h"

// START globals section

// how many containers have we called docker service scale to overall
int total_scaled = 0;

// initialized by docker service scale, but pipes not ready
int num_initialized = 0;

// number of containers requested by gw, but not fulfilled by scaler
int num_requested = 0;

// END globals section

/* Initialize docker stack to bring the services up */
int
init_stack(void) {
        // docker command to start container
        const char *command = "docker stack deploy -c ./scaler/docker-compose.yml skeleton";
        int ret = system(command);

        if (WEXITSTATUS(ret) != 0)
                return -1;

        return 0;
}

// initialize "scale" more containers (they will start in the "warm queue")
int
scale_docker(int scale) {
        char docker_call[100];
        int i;
        for (i = total_scaled + 1; i <= scale + total_scaled; i++) {
                // create the pipes for a specific container ID
                if (create_pipes(i) == -1) {
                        // failed to make pipe
                        printf("Could not create pipes to scale containers\n");
                        return -1;
                }
        }

        // increment number of containers that were scaled
        total_scaled += scale;

        sprintf(docker_call, "docker service scale %s_%s=%d", SERVICE, SERVICE, total_scaled);

        int ret = system(docker_call);
        if (WEXITSTATUS(ret) != 0)
                return -1;

        return 0;
}

/* Garbage collector helper to kill container by ID */
int
kill_container_id(char *hash_id) {
        char docker_call[36];
        // docker_call string is 36 characters with a 12 character container hash id + \0
        // 36 characters -> docker rm -f <container hash id>\0
        sprintf(docker_call, "docker rm -f %s", hash_id);
        return system(docker_call);
}

/* Helper for testing, kill the docker service */
void
kill_docker(void) {
        char docker_call[100];
        sprintf(docker_call, "docker stack rm %s", SERVICE);
        if (system(docker_call) < 0) {
                printf("Failed to stop docker stack\n");
        }
}

void
cleanup(void) {
        kill_docker();
        clean_pipes();
}

int
move_buffer_to_container(void) {
        if (rte_atomic16_read(&num_running_containers) >= max_containers) {
                // cannot afford to add new container
                perror("Max containers/flows hit");
                return -1;
        }

        // loop while there are buffered flow rings, and warm containers to service them
        while (rte_ring_count(container_init_ring) > 0 && rte_ring_count(scale_buffer_ring) > 0) {
                struct pipe_fds *pipe = NULL;
                struct onvm_ft_ipv4_5tuple *flow = NULL;

                if (rte_ring_dequeue(scale_buffer_ring, (void **)(&pipe)) == -1) {
                        perror("Couldn't dequeue container_init_ring");
                        continue;
                }

                if (rte_ring_dequeue(container_init_ring, (void **)(&flow)) == -1) {
                        perror("Couldn't dequeue container_init_ring");
                        continue;
                }

                /*
                 * New containers/pipes are ready and we have an unassigned IP flow
                 * Get the first available buffered flow (maybe random for fairness)
                 * De-buffer every packet from this flow and push to the tx pipe fd
                 * Add to flow table with <flow>:<struct container> (with pipe fds and other data)
                 * Add rx pipe to epoll for polling
                 */
                if (dequeue_and_free_buffer_map(flow, pipe->tx_pipe, pipe->rx_pipe) < 0) {
                        // -1 from fn means flow failed lookup
                        // in case flow fails, we can retry this container/pipe later
                        if (rte_ring_enqueue(scale_buffer_ring, (void *)pipe) < 0) {
                                printf("Couldn't put pipe back in scale buffer\n");
                                return -1;
                        }
                        continue;
                }
                add_fd_epoll(pipe->rx_pipe);
        }

        return 0;
}

/* scaler runs to maintain warm containers and garbage collect old ones */
void
scaler(void) {
        // initialize, to be modified by pipes.c
        created_not_ready = 0;

        if (init_pipe_dir() != 0) {
                printf("Failed to initialize pipe directory %s\n", PIPE_DIR);
                return;
        }

        if (init_stack() == -1) {
                printf("Failed to start up docker stack\n");
                return;
        }

        int num_to_scale;

        int initialized = 0;
        for (; worker_keep_running;) {
                num_to_scale = WARM_CONTAINERS_REQUIRED - (rte_ring_count(scale_buffer_ring) + created_not_ready);
                if (num_to_scale > 0 && !initialized) {
                        initialized = 1;
                        /*
                         * The number of initialized + "not ready" containers represents
                         * the current amount of "warm" containers
                         * Need to make sure this number stays constant (psuedo-auto-scaling)
                         */
                        printf("Need to scale %d more containers\n", num_to_scale);
                        if (scale_docker(num_to_scale) != 0) {
                                printf("Failed to scale containers\n");
                                break;
                        }
                } else if (unlikely(num_to_scale) < 0) {
                        printf("Failure: The number to scale should not be negative.");
                        break;
                } else {
                        // no new flows, just sleep for a bit
                        sleep(1);
                }

                if (created_not_ready > 0) {
                        // only test pipe readiness if there are some that haven't succeeded
                        ready_pipes();
                } else if (unlikely(created_not_ready) < 0) {
                        printf("Failure: We shouldn't have a negative amount of pipes.");
                        break;
                }

                move_buffer_to_container();
        }

        cleanup();
        printf("Scaler thread exiting\n");
}

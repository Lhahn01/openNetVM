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
 * scale.c - A container auto-scaling API for gateway to communicate with.
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
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_per_lcore.h>
#include <rte_ring.h>

#include "api_gateway.h"
#include "scaler.h"

// START globals section

/*
 * represents a queue of "warm" containers
 * scaler only needs to keep track of pipe ID (auto-incrementing)
 *   for each container
 * - (QUEUE_FRONT - QUEUE_BACK) is the number of "warm" containers
 * - QUEUE_FRONT++ increases the size of the stack (during scaling)
 * - QUEUE_BACK++ decreases q size
 */
int QUEUE_FRONT = 0;
int QUEUE_BACK = 0;

// service name for the docker containers
const char* SERVICE = "skeleton";

// END globals section

/* API Calls below */
/* Return the number of containers up in docker-compose */
int
num_running_containers() {
        FILE* fp;
        int id_hash_length = 14;
        char container_id[id_hash_length];
        int num = 0;
        char docker_call[100];

        sprintf(docker_call, "docker ps -aq --filter='name=%s'", SERVICE);
        fp = popen(docker_call, "r");
        if (!fp) {
                printf("Docker failed to execute\n");
                return -1;
        }

        while (fgets(container_id, id_hash_length, fp) != NULL) {
                // remove new line character
                container_id[id_hash_length - 2] = '\0';
                printf("Container hash: %s\n", container_id);
                num++;
        }

        // close file descriptor
        pclose(fp);

        return num;
}

/* Create rx and tx pipes in /tmp/rx and /tmp/tx */
int
create_pipes(int ref) {
        // TODO: insert pipe code here
        return 0;
}

/* Initialize docker stack to bring the services up */
int
init_stack() {
        /*
         * Set up first named pipe
         * Initialize docker container
         * Place container ID in the shared struct of "warm" containers
         */

        // set up first named pipe
        if (create_pipes(++QUEUE_FRONT) == -1)
                // failed pipe creation
                return -1;

        // docker command to start container
        const char* command = "docker stack deploy -c ./scaler/docker-compose.yml skeleton";
        int ret = system(command);

        if (WEXITSTATUS(ret) != 0)
                return -1;

        return 0;
}

// initialize "scale" more containers (they will start in the "warm queue")
int
scale_docker(int scale) {
        char docker_call[100];
        for (int i = QUEUE_FRONT + 1; i <= scale + QUEUE_FRONT; i++) {
                // create the pipes for a specific container ID
                printf("scale %d\n", i);
                if (create_pipes(i) == -1) {
                        // failed to make pipe
                        printf("Could not create pipes to scale containers\n");
                        return -1;
                }
        }

        // increment number of containers that were scaled
        QUEUE_FRONT += scale;

        sprintf(docker_call, "docker service scale %s_%s=%d", SERVICE, SERVICE, QUEUE_FRONT);

        int ret = system(docker_call);
        if (WEXITSTATUS(ret) != 0)
                return -1;

        return 0;
}

/* Garbage collector helper to kill container by ID */
int
kill_container_id(char* hash_id) {
        char docker_call[36];
        // docker_call string is 36 characters with a 12 character container hash id + \0
        // 36 characters -> docker rm -f <container hash id>\0
        sprintf(docker_call, "docker rm -f %s", hash_id);
        return system(docker_call);
}

/* Helper for testing, kill the docker service */
void
kill_docker() {
        char docker_call[100];
        sprintf(docker_call, "docker stack rm %s", SERVICE);
        system(docker_call);
}

/* scaler runs to maintain warm containers and garbage collect old ones */
void*
scaler(void* in) {
        if (init_stack() == -1) {
                printf("Failed to start up docker stack\n");
                return NULL;
        }

        while (1) {
                void* msg;
                if (rte_ring_dequeue(to_scale_ring, &msg) < 0) {
                        // no new flows yet, just do auto-scaling work
                        usleep(5);
                        continue;
                }

                // gateway asked us to do something
                int num_requested = (int)msg;
                printf("Received %d containers\n", num_requested);
                int num_warm = QUEUE_FRONT - QUEUE_BACK;
                int num_to_scale = num_requested - num_warm;

                if (num_to_scale > 0) {
                        // need to scale more to answer the gateway's request
                        scale_docker(num_to_scale);
                }

                // now that they're scaled, enqueue to the scale_to_gate
                if (rte_ring_enqueue(to_gate_ring, msg) < 0) {
                        printf("Failed to send containers to gateway\n");
                } else {
                        // success, dequeue from warm container list
                        QUEUE_BACK += num_requested;
                }

                break;
        }

        printf("Scaler thread exiting\n");
        kill_docker();
        return NULL;
}
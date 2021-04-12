#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

// cont_nf reads through the host's write (tx) pipe
#define CONT_RX_PIPE_NAME "/pipe/tx"
// and writes (tx) with the pipe the host reads (rx) from
#define CONT_TX_PIPE_NAME "/pipe/rx"

#define RETRY_OPEN_PIPES 20

// TODO: not sure we still need this if pies are created on the host side
int
create_pipes(void);

/*
 * Open rx and tx pipes (created on host-side)
 * Return 0 on success, -1 on failure
 */
int
open_pipes(void);

/* Cleanup pipes and close fds */
void
pipe_cleanup(void);

/* Helper to fill packet from RX pipe */
struct rte_mbuf*
read_packet(void);

/* Helper to send packet out through network */
int
write_packet(struct rte_mbuf*);

void
receive_packets(void);

#include "api_gateway.h"

struct data *
get_ipv4_dst(struct rte_mbuf *pkt) {
        struct data *data;
        // TODO: don't malloc inside pkt_handler
        struct onvm_ft_ipv4_5tuple *key = malloc(sizeof(struct onvm_ft_ipv4_5tuple));

        int ret = onvm_ft_fill_key(key, pkt);
        if (ret < 0)
                return NULL;

        int tbl_index = onvm_ft_lookup_key((struct onvm_ft *)em_tbl, key, (char **)&data);
        if (tbl_index < 0) {
                onvm_ft_add_key((struct onvm_ft *)em_tbl, key, (char **)&data);
                data->dest = 0;
                data->cont_idx = -1;
                data->pkts = 0; 
                data->num_buffered = 0;
                rte_rwlock_init(&data->lock);
                rte_ring_enqueue(container_init_ring, (void *)key);
        } else if (data->dest > 0) {
                // printf("\n[Sending non-unique] Src %d:%d Dst %d:%d\n", key->src_addr, key->src_port, key->dst_addr,
                //        key->dst_port);
        }
        return data;
}

void
print_key(struct rte_mbuf *pkt) {
        struct onvm_ft_ipv4_5tuple key;

        int ret = onvm_ft_fill_key(&key, pkt);
        if (ret < 0)
                return;

        // printf("Src %d:%d Dst %d:%d\n", key.src_addr, key.src_port, key.dst_addr, key.dst_port);
}

int
setup_hash(void) {
        em_tbl = onvm_ft_create(HASH_ENTRIES, sizeof(struct data));
        if (em_tbl == NULL) {
                printf("Unable to create flow table");
                return -1;
        }

        add_rules(em_tbl, "ipv4_rules_file.txt", ONVM_TABLE_EM);
        return 0;
}

const char cb_port_delim[] = ":";

int
get_cb_field(char **in, uint32_t *fd, int base, unsigned long lim, char dlm) {
        unsigned long val;
        char *end;

        errno = 0;
        val = strtoul(*in, &end, base);
        if (errno != 0 || end[0] != dlm || val > lim)
                return -EINVAL;
        *fd = (uint32_t)val;
        *in = end + 1;
        return 0;
}

int
parse_ipv4_net(char *in, uint32_t *addr, uint32_t *depth) {
        uint32_t a, b, c, d, m;

        if (get_cb_field(&in, &a, 0, UINT8_MAX, '.'))
                return -EINVAL;
        if (get_cb_field(&in, &b, 0, UINT8_MAX, '.'))
                return -EINVAL;
        if (get_cb_field(&in, &c, 0, UINT8_MAX, '.'))
                return -EINVAL;
        if (get_cb_field(&in, &d, 0, UINT8_MAX, '/'))
                return -EINVAL;
        if (get_cb_field(&in, &m, 0, sizeof(uint32_t) * CHAR_BIT, 0))
                return -EINVAL;
        addr[0] = RTE_IPV4(a, b, c, d);
        depth[0] = m;
        return 0;
}

/* This function fills the key and return the destination or action to be stored in the table entry.*/
int
parse_ipv4_5tuple_rule(char *str, struct onvm_parser_ipv4_5tuple *ipv4_tuple) {
        int i, ret;
        char *s, *sp, *in[CB_FLD_NUM];
        static const char *dlm = " \t\n";
        int dim = CB_FLD_NUM;
        uint32_t temp;

        struct onvm_ft_ipv4_5tuple *key = &ipv4_tuple->key;
        s = str;
        for (i = 0; i != dim; i++, s = NULL) {
                in[i] = strtok_r(s, dlm, &sp);
                if (in[i] == NULL)
                        return -EINVAL;
        }

        ret = parse_ipv4_net(in[CB_FLD_SRC_ADDR], &key->src_addr, &ipv4_tuple->src_addr_depth);
        if (ret < 0) {
                return ret;
        }

        ret = parse_ipv4_net(in[CB_FLD_DST_ADDR], &key->dst_addr, &ipv4_tuple->dst_addr_depth);
        if (ret < 0) {
                return ret;
        }

        if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim, sizeof(cb_port_delim)) != 0)
                return -EINVAL;

        if (get_cb_field(&in[CB_FLD_SRC_PORT], &temp, 0, UINT16_MAX, 0))
                return -EINVAL;
        key->src_port = (uint16_t)temp;

        if (get_cb_field(&in[CB_FLD_DST_PORT], &temp, 0, UINT16_MAX, 0))
                return -EINVAL;
        key->dst_port = (uint16_t)temp;

        if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim, sizeof(cb_port_delim)) != 0)
                return -EINVAL;

        if (get_cb_field(&in[CB_FLD_PROTO], &temp, 0, UINT8_MAX, 0))
                return -EINVAL;
        key->proto = (uint8_t)temp;

        if (get_cb_field(&in[CB_FLD_DEST], &temp, 0, UINT16_MAX, 0))
                return -EINVAL;

        // Return the destination or action to be performed by the NF.
        return (uint16_t)temp;
}

/* Bypass comment and empty lines */
int
is_bypass_line(char *buff) {
        int i = 0;

        /* comment line */
        if (buff[0] == COMMENT_LEAD_CHAR)
                return 1;
        /* empty line */
        while (buff[i] != '\0') {
                if (!isspace(buff[i]))
                        return 0;
                i++;
        }
        return 1;
}

int
add_rules(void *tbl, const char *rule_path, int table_type) {
        FILE *fh;
        char buff[LINE_MAX];
        unsigned int i = 0;
        struct onvm_parser_ipv4_5tuple ipv4_tuple;
        int ret;
        fh = fopen(rule_path, "rb");
        if (fh == NULL)
                rte_exit(EXIT_FAILURE, "%s: fopen %s failed\n", __func__, rule_path);

        ret = fseek(fh, 0, SEEK_SET);
        if (ret)
                rte_exit(EXIT_FAILURE, "%s: fseek %d failed\n", __func__, ret);
        i = 0;
        while (fgets(buff, LINE_MAX, fh) != NULL) {
                i++;

                if (is_bypass_line(buff))
                        continue;

                uint8_t dest = parse_ipv4_5tuple_rule(buff, &ipv4_tuple);
                // TODO: fix error with comparison
                // error: comparison is always false due to limited range of data type [-Werror=type-limits]
                // if (dest < 0)
                //         rte_exit(EXIT_FAILURE, "%s Line %u: parse rules error\n", rule_path, i);

                struct data *data = NULL;
                int tbl_index = -EINVAL;
                if (table_type == ONVM_TABLE_EM) {
                        tbl_index = onvm_ft_add_key((struct onvm_ft *)tbl, &ipv4_tuple.key, (char **)&data);
                } else if (table_type == ONVM_TABLE_LPM) {
                        // Adds to the lpm table using the src ip adress.
                        tbl_index = rte_lpm_add((struct rte_lpm *)tbl, ipv4_tuple.key.src_addr,
                                                ipv4_tuple.src_addr_depth, dest);
                }
                data->dest = dest;
                data->cont_idx = -1;
                data->pkts = 0; 
                if (tbl_index < 0)
                        rte_exit(EXIT_FAILURE, "Unable to add entry %u\n", i);
        }

        fclose(fh);
        return 0;
}

/* Functions for the buffer map data structure
 * Responsible for mapping IP flow to ring of
 * buffered packets
 * Gateway fills this and buffer removes when
 * containers are ready from scaler
 */

/*
 * TODO: @bdevierno1 functions below were for buffer map, but some still apply
 * most of the functions will be used, but need to be changed to use an array
 * instead of ring for each flow buffer
 */

int
setup_buffer_map(void) {
        buffer_map = onvm_ft_create(max_containers, sizeof(struct rte_ring *));
        if (buffer_map == NULL) {
                printf("Unable to create buffer map");
                return -1;
        }

        return 0;
}

/* Retrieve the ring buffering this IP flow */
struct rte_ring *
get_buffer_flow(struct onvm_ft_ipv4_5tuple key) {
        struct rte_ring *ring = NULL;

        int tbl_index = onvm_ft_lookup_key(buffer_map, &key, (char **)&ring);
        if (tbl_index < 0)
                return NULL;

        return ring;
}

const char *
get_flow_queue_name(struct onvm_ft_ipv4_5tuple key) {
        static char buffer[sizeof(FLOW_RING_NAME) + 2];

        snprintf(buffer, sizeof(buffer) - 1, FLOW_RING_NAME, key.src_addr, key.src_port);
        return buffer;
}

/* Create new ring for buffer map */
struct rte_ring *
new_ring_buffer_map(struct onvm_ft_ipv4_5tuple key) {
        const unsigned flags = 0;
        const char *q_name = get_flow_queue_name(key);

        return rte_ring_create(q_name, MAX_FLOW_PACKETS, rte_socket_id(), flags);
}

/* Add packet to buffer map, determine if it's new (needs new ring) */
int
add_buffer_map(struct rte_mbuf *pkt) {
        struct onvm_ft_ipv4_5tuple key;
        int ret = onvm_ft_fill_key(&key, pkt);
        if (ret < 0) {
                perror("Packet couldn't be converted to ipv4_5tuple");
                return -1;
        }

        struct rte_ring *ring = get_buffer_flow(key);
        if (ring == NULL) {
                // first of it's kind, need new ring
                ring = new_ring_buffer_map(key);
                if (ring == NULL) {
                        perror("Failed to create ring for buffer map.");
                        return -1;
                }
        }

        // when dequeueing all packets
        rte_ring_enqueue(ring, (void *)pkt);
        return 0;
}

/* Dequeue entire flow ring and free flow from buffer map */
int32_t
dequeue_and_free_buffer_map(struct onvm_ft_ipv4_5tuple *key, int tx_fd, int rx_fd) {
        struct data *data;

        int tbl_index = onvm_ft_lookup_key((struct onvm_ft *)em_tbl, key, (char **)&data);
        if (tbl_index < 0) {
                RTE_LOG(INFO, APP, "Lookup failed in buffer map.\n");
                return -1;
        }

        rte_rwlock_write_lock(&data->lock);

        int i = 0;
        // write buffered packets
        // printf("\n[Sending new flow] Src %d:%d Dst %d:%d\n", key->src_addr, key->src_port, key->dst_addr,
        //        key->dst_port);
        // printf("Container RX: %d and TX: %d\n", tx_fd, rx_fd);
        while (i < data->num_buffered) {
                write_packet(tx_fd, data->buffer[i]);
                i++;
        }
        data->num_buffered = 0;
        rte_rwlock_write_unlock(&data->lock);

        data->poll_fd = rx_fd;
        // send packets here
        data->dest = tx_fd;

        return 0;
}

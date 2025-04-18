#include "structs_enums.h"
#include <stdbool.h>
#include "my_structs.h"

void process_packets(int ingress_port);

void process_packets_vlan(int ingress_port);

void scatter_gather_packets(int in_port, int out_port, int qid,
                            volatile bool *fq, struct rte_mempool *mp,
                            enum SG_TYPE sg_type, struct my_stats *stats);

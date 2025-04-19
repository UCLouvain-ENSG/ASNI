#define print_stats() \
            printf("RESULT-SERVER-TESTTIME %f\n", time_elapsed);\
            printf("RESULT-THROUGHPUT %fGbps\n",\
                   (((nb_byte + 24 * counter_total) * 8) / time_elapsed) /\
                       1000000000);\
            printf("RESULT-COUNT %ld\n", counter_total);\
            printf("RESULT-BURST_SIZE %ld\n", counter_total/counter);\
            if (time_elapsed > 0) {\
                printf("RESULT-PPS %f\n", (double)counter_total / (time_elapsed));\
                printf("RESULT-MPPS %f\n",\
                   ((double)counter_total / (time_elapsed)) / 1000000);\
            }\
            printf("RESULT-GOODPUT %fGbps\n",\
                   ((nb_byte * 8) / time_elapsed) / 1000000000);\
            printf("RESULT-USEFULKCYCLES %lu\n", useful_cycles / 1000);\
            if (counter_total > 0)\
                printf("RESULT-CYCLES-PER-PACKET %lu\n",\
                       useful_cycles / counter_total);\
            if (useful_cycles + useless_cycles > 0)\
                printf("RESULT-CPU-LOAD %f\n",\
                       (double)useful_cycles /\
                           (double)(useful_cycles + useless_cycles));

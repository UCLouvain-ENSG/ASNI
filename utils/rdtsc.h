unsigned int find_rdtsc_overhead(void);

unsigned int find_rdtsc_overhead() {
    const int trials = 1000000;

    unsigned long long tot = 0;

    for (int i = 0; i < trials; ++i) {
        unsigned long long t_begin = rte_get_tsc_cycles();
        unsigned long long t_end = rte_get_tsc_cycles();
        tot += (t_end - t_begin);
    }
    return tot / trials;
}
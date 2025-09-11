#include <stddef.h> // size_t
#include <stdint.h> // uint64_t

uint8_t **memory_addresses(const struct addr_space *addr);
int length(const struct addr_space *addr);

struct measurement *spoiler_measure(uint8_t *write, size_t write_buf_size, uint8_t *read);
void spoiler_free(struct measurement *m);

const uint64_t *measurements(const struct measurement *m);
const uint64_t *diffs(const struct measurement *m);

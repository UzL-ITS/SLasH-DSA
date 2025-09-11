#include "../include/misc.h"
#include "../include/spoiler.h"

// Include pow library
#include <math.h>
#include <assert.h>

struct measurement
{
	uint64_t *measurementBuffer;
	uint64_t *diffBuffer;
};

struct measurement *spoiler_measure(uint8_t *buffer, size_t buf_size, uint8_t *read)
{
	struct measurement *ret = malloc(sizeof(struct measurement));
	size_t page_count = buf_size / PAGE_SIZE;
	ret->measurementBuffer = malloc(page_count * sizeof(uint64_t));
	ret->diffBuffer = malloc(page_count * sizeof(uint64_t));

	////////////////////////////////SPOILER////////////////////////////////////
	// Warmup loop to avoid initial spike in timings
#define PASS asm("nop")

	for (int i = 0; i < 1000000; i++)
		PASS;
#define WINDOW 64
	{
		int t2_prev = 0;
		// for each page in [WINDOW...PAGE_COUNT)
		for (int p = WINDOW; p < page_count; p++)
		{
			uint64_t total = 0;
			int cc = 0;
			for (int r = 0; r < SPOILER_ROUNDS; r++)
			{
				uint32_t tt = 0;
				for (int i = WINDOW; i >= 0; i--)
				{
					buffer[(p - i) * PAGE_SIZE] = 0;
				}
				measure(read, &tt);

				if (tt < THRESH_OUTLIER)
				{
					total = total + tt;
					cc++;
				}
			}

			if (cc > 0)
			{
				uint64_t result = total / cc;
				ret->measurementBuffer[p] = result;
				if (total / SPOILER_ROUNDS < t2_prev)
				{
					ret->diffBuffer[p] = 0;
				}
				else
				{
					ret->diffBuffer[p] = (total / SPOILER_ROUNDS) - t2_prev;
				}
			}
			t2_prev = total / SPOILER_ROUNDS;
		}
	}
	return ret;
}

void spoiler_free(struct measurement *m)
{
	free(m->measurementBuffer);
	free(m->diffBuffer);
	free(m);
}

inline uint8_t **memory_addresses(const struct addr_space *addr)
{
	return addr->memory_addresses;
}

inline int length(const struct addr_space *addr)
{
	return addr->length;
}

const uint64_t *measurements(const struct measurement *m)
{
	return m->measurementBuffer;
}

const uint64_t *diffs(const struct measurement *m)
{
	return m->diffBuffer;
}

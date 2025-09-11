#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

#define INPUT_SIZE 32
#define OUTPUT_SIZE 32
#define ITERATIONS 10000000

// Thread data structure
typedef struct {
    const unsigned char *input;
    unsigned char *output;
    int iterations;
    double elapsed_time;
    int thread_id;
} thread_data_t;

// Function to get current time in nanoseconds
uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Benchmark SHA-256
double benchmark_sha256(const unsigned char *input, unsigned char *output, int iterations) {
    uint64_t start_time = get_time_ns();
    
    for (int i = 0; i < iterations; i++) {
        SHA256(input, INPUT_SIZE, output);
    }
    
    uint64_t end_time = get_time_ns();
    return (double)(end_time - start_time) / 1000000.0; // Convert to milliseconds
}

// Benchmark SHAKE-256
double benchmark_shake256(const unsigned char *input, unsigned char *output, int iterations) {
    uint64_t start_time = get_time_ns();
    
    for (int i = 0; i < iterations; i++) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create EVP_MD_CTX\n");
            return -1.0;
        }
        
        if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
            fprintf(stderr, "Failed to initialize SHAKE-256\n");
            EVP_MD_CTX_free(ctx);
            return -1.0;
        }
        
        if (EVP_DigestUpdate(ctx, input, INPUT_SIZE) != 1) {
            fprintf(stderr, "Failed to update SHAKE-256\n");
            EVP_MD_CTX_free(ctx);
            return -1.0;
        }
        
        if (EVP_DigestFinalXOF(ctx, output, OUTPUT_SIZE) != 1) {
            fprintf(stderr, "Failed to finalize SHAKE-256\n");
            EVP_MD_CTX_free(ctx);
            return -1.0;
        }
        
        EVP_MD_CTX_free(ctx);
    }
    
    uint64_t end_time = get_time_ns();
    return (double)(end_time - start_time) / 1000000.0; // Convert to milliseconds
}

// Thread worker function for SHA-256
void *sha256_worker(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    uint64_t start_time = get_time_ns();
    
    for (int i = 0; i < data->iterations; i++) {
        SHA256(data->input, INPUT_SIZE, data->output);
    }
    
    uint64_t end_time = get_time_ns();
    data->elapsed_time = (double)(end_time - start_time) / 1000000.0;
    return NULL;
}

// Thread worker function for SHAKE-256
void *shake256_worker(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    uint64_t start_time = get_time_ns();
    
    for (int i = 0; i < data->iterations; i++) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Thread %d: Failed to create EVP_MD_CTX\n", data->thread_id);
            data->elapsed_time = -1.0;
            return NULL;
        }
        
        if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
            fprintf(stderr, "Thread %d: Failed to initialize SHAKE-256\n", data->thread_id);
            EVP_MD_CTX_free(ctx);
            data->elapsed_time = -1.0;
            return NULL;
        }
        
        if (EVP_DigestUpdate(ctx, data->input, INPUT_SIZE) != 1) {
            fprintf(stderr, "Thread %d: Failed to update SHAKE-256\n", data->thread_id);
            EVP_MD_CTX_free(ctx);
            data->elapsed_time = -1.0;
            return NULL;
        }
        
        if (EVP_DigestFinalXOF(ctx, data->output, OUTPUT_SIZE) != 1) {
            fprintf(stderr, "Thread %d: Failed to finalize SHAKE-256\n", data->thread_id);
            EVP_MD_CTX_free(ctx);
            data->elapsed_time = -1.0;
            return NULL;
        }
        
        EVP_MD_CTX_free(ctx);
    }
    
    uint64_t end_time = get_time_ns();
    data->elapsed_time = (double)(end_time - start_time) / 1000000.0;
    return NULL;
}

// Parallel benchmark for SHA-256
double benchmark_sha256_parallel(const unsigned char *input, unsigned char *output, int iterations, int num_threads) {
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_data_t *thread_data = malloc(num_threads * sizeof(thread_data_t));
    unsigned char *thread_outputs = malloc(num_threads * SHA256_DIGEST_LENGTH);
    
    if (!threads || !thread_data || !thread_outputs) {
        fprintf(stderr, "Failed to allocate memory for threads\n");
        free(threads);
        free(thread_data);
        free(thread_outputs);
        return -1.0;
    }
    
    int iterations_per_thread = iterations / num_threads;
    int remaining_iterations = iterations % num_threads;
    
    uint64_t start_time = get_time_ns();
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].input = input;
        thread_data[i].output = &thread_outputs[i * SHA256_DIGEST_LENGTH];
        thread_data[i].iterations = iterations_per_thread + (i < remaining_iterations ? 1 : 0);
        thread_data[i].thread_id = i;
        
        if (pthread_create(&threads[i], NULL, sha256_worker, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            free(threads);
            free(thread_data);
            free(thread_outputs);
            return -1.0;
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    uint64_t end_time = get_time_ns();
    
    // Copy the last thread's output to the main output buffer
    memcpy(output, &thread_outputs[(num_threads - 1) * SHA256_DIGEST_LENGTH], SHA256_DIGEST_LENGTH);
    
    free(threads);
    free(thread_data);
    free(thread_outputs);
    
    return (double)(end_time - start_time) / 1000000.0;
}

// Parallel benchmark for SHAKE-256
double benchmark_shake256_parallel(const unsigned char *input, unsigned char *output, int iterations, int num_threads) {
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_data_t *thread_data = malloc(num_threads * sizeof(thread_data_t));
    unsigned char *thread_outputs = malloc(num_threads * OUTPUT_SIZE);
    
    if (!threads || !thread_data || !thread_outputs) {
        fprintf(stderr, "Failed to allocate memory for threads\n");
        free(threads);
        free(thread_data);
        free(thread_outputs);
        return -1.0;
    }
    
    int iterations_per_thread = iterations / num_threads;
    int remaining_iterations = iterations % num_threads;
    
    uint64_t start_time = get_time_ns();
    
    // Create threads
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].input = input;
        thread_data[i].output = &thread_outputs[i * OUTPUT_SIZE];
        thread_data[i].iterations = iterations_per_thread + (i < remaining_iterations ? 1 : 0);
        thread_data[i].thread_id = i;
        
        if (pthread_create(&threads[i], NULL, shake256_worker, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            free(threads);
            free(thread_data);
            free(thread_outputs);
            return -1.0;
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        if (thread_data[i].elapsed_time < 0) {
            free(threads);
            free(thread_data);
            free(thread_outputs);
            return -1.0;
        }
    }
    
    uint64_t end_time = get_time_ns();
    
    // Copy the last thread's output to the main output buffer
    memcpy(output, &thread_outputs[(num_threads - 1) * OUTPUT_SIZE], OUTPUT_SIZE);
    
    free(threads);
    free(thread_data);
    free(thread_outputs);
    
    return (double)(end_time - start_time) / 1000000.0;
}

// Generate random input data
void generate_random_input(unsigned char *input, size_t size) {
    for (size_t i = 0; i < size; i++) {
        input[i] = rand() & 0xFF;
    }
}

// Print hash in hexadecimal format
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Cross-platform function to get number of CPU cores
int get_cpu_cores() {
#ifdef __APPLE__
    int num_cores;
    size_t size = sizeof(num_cores);
    if (sysctlbyname("hw.ncpu", &num_cores, &size, NULL, 0) == 0) {
        return num_cores;
    }
    return 1; // fallback to single core
#elif defined(_SC_NPROCESSORS_ONLN)
    // Linux and other POSIX systems
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    return (num_cores > 0) ? num_cores : 1;
#else
    // Fallback for other systems
    return 1;
#endif
}

int main(void) {
    printf("Hash Benchmark: SHA-256 vs SHAKE-256 (Parallelized)\n");
    printf("Input size: %d bytes\n", INPUT_SIZE);
    printf("Output size: %d bytes\n", OUTPUT_SIZE);
    printf("Iterations: %d\n", ITERATIONS);
    
    // Get number of CPU cores
    int num_cores = get_cpu_cores();
    printf("Number of CPU cores: %d\n\n", num_cores);
    
    // Seed random number generator
    srand(time(NULL));
    
    // Allocate buffers
    unsigned char input[INPUT_SIZE];
    unsigned char sha256_output[SHA256_DIGEST_LENGTH];
    unsigned char shake256_output[OUTPUT_SIZE];
    
    // Generate random input
    generate_random_input(input, INPUT_SIZE);
    
    printf("Input data: ");
    print_hex(input, INPUT_SIZE);
    printf("\n");
    
    // Benchmark SHA-256 (single-threaded)
    printf("Benchmarking SHA-256 (single-threaded)...\n");
    double sha256_time_single = benchmark_sha256(input, sha256_output, ITERATIONS);
    if (sha256_time_single < 0) {
        fprintf(stderr, "SHA-256 single-threaded benchmark failed\n");
        return 1;
    }
    
    printf("SHA-256 output: ");
    print_hex(sha256_output, OUTPUT_SIZE);
    printf("SHA-256 (single) time: %.2f ms for %d iterations\n", sha256_time_single, ITERATIONS);
    printf("SHA-256 (single) average: %.6f ms per hash\n", sha256_time_single / ITERATIONS);
    printf("SHA-256 (single) throughput: %.2f hashes/second\n\n", ITERATIONS * 1000.0 / sha256_time_single);
    
    // Benchmark SHA-256 (multi-threaded)
    printf("Benchmarking SHA-256 (multi-threaded)...\n");
    double sha256_time_parallel = benchmark_sha256_parallel(input, sha256_output, ITERATIONS, num_cores);
    if (sha256_time_parallel < 0) {
        fprintf(stderr, "SHA-256 multi-threaded benchmark failed\n");
        return 1;
    }
    
    printf("SHA-256 (parallel) time: %.2f ms for %d iterations\n", sha256_time_parallel, ITERATIONS);
    printf("SHA-256 (parallel) average: %.6f ms per hash\n", sha256_time_parallel / ITERATIONS);
    printf("SHA-256 (parallel) throughput: %.2f hashes/second\n", ITERATIONS * 1000.0 / sha256_time_parallel);
    printf("SHA-256 speedup: %.2fx\n\n", sha256_time_single / sha256_time_parallel);
    
    // Benchmark SHAKE-256 (single-threaded)
    printf("Benchmarking SHAKE-256 (single-threaded)...\n");
    double shake256_time_single = benchmark_shake256(input, shake256_output, ITERATIONS);
    if (shake256_time_single < 0) {
        fprintf(stderr, "SHAKE-256 single-threaded benchmark failed\n");
        return 1;
    }
    
    printf("SHAKE-256 output: ");
    print_hex(shake256_output, OUTPUT_SIZE);
    printf("SHAKE-256 (single) time: %.2f ms for %d iterations\n", shake256_time_single, ITERATIONS);
    printf("SHAKE-256 (single) average: %.6f ms per hash\n", shake256_time_single / ITERATIONS);
    printf("SHAKE-256 (single) throughput: %.2f hashes/second\n\n", ITERATIONS * 1000.0 / shake256_time_single);
    
    // Benchmark SHAKE-256 (multi-threaded)
    printf("Benchmarking SHAKE-256 (multi-threaded)...\n");
    double shake256_time_parallel = benchmark_shake256_parallel(input, shake256_output, ITERATIONS, num_cores);
    if (shake256_time_parallel < 0) {
        fprintf(stderr, "SHAKE-256 multi-threaded benchmark failed\n");
        return 1;
    }
    
    printf("SHAKE-256 (parallel) time: %.2f ms for %d iterations\n", shake256_time_parallel, ITERATIONS);
    printf("SHAKE-256 (parallel) average: %.6f ms per hash\n", shake256_time_parallel / ITERATIONS);
    printf("SHAKE-256 (parallel) throughput: %.2f hashes/second\n", ITERATIONS * 1000.0 / shake256_time_parallel);
    printf("SHAKE-256 speedup: %.2fx\n\n", shake256_time_parallel > 0 ? shake256_time_single / shake256_time_parallel : 0);
    
    // Performance comparison
    printf("Performance comparison:\n");
    printf("Single-threaded: ");
    if (sha256_time_single > 0 && shake256_time_single > 0) {
        double ratio_single = sha256_time_single / shake256_time_single;
        if (ratio_single > 1.0) {
            printf("SHAKE-256 is %.2fx faster than SHA-256\n", ratio_single);
        } else {
            printf("SHA-256 is %.2fx faster than SHAKE-256\n", 1.0 / ratio_single);
        }
    }
    
    printf("Multi-threaded: ");
    if (sha256_time_parallel > 0 && shake256_time_parallel > 0) {
        double ratio_parallel = sha256_time_parallel / shake256_time_parallel;
        if (ratio_parallel > 1.0) {
            printf("SHAKE-256 is %.2fx faster than SHA-256\n", ratio_parallel);
        } else {
            printf("SHA-256 is %.2fx faster than SHAKE-256\n", 1.0 / ratio_parallel);
        }
    }
    
    return 0;
}

# Hash Benchmark

A performance benchmark comparing SHA-256 and SHAKE-256 hash functions with 32-byte inputs and 32-byte outputs. **Now supports parallel execution across all CPU cores for maximum performance testing.**

## Features

- Benchmarks SHA-256 using OpenSSL's optimized implementation
- Benchmarks SHAKE-256 (extensible output function) using OpenSSL's EVP interface
- **Parallel execution using pthreads to utilize all available CPU cores**
- **Compares single-threaded vs multi-threaded performance**
- **Automatic CPU core detection and load distribution**
- Uses 32-byte input and output sizes for fair comparison
- Measures performance over 1,000,000 iterations for statistical accuracy
- Reports timing, throughput, speedup ratios, and performance comparisons

## Requirements

- GCC compiler with C99 support
- OpenSSL development libraries (version 1.1.0 or later for SHAKE support)
- **pthread library (usually included with GCC on Linux/Unix systems)**
- **Cross-platform compatibility: Linux, macOS, and other POSIX systems**

### Installing OpenSSL

**macOS:**
```bash
# Install via Homebrew
brew install openssl

# Or use the convenience target
make install-deps-macos
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libssl-dev
```

**Linux (CentOS/RHEL):**
```bash
sudo yum install openssl-devel
```

**Linux (Fedora):**
```bash
sudo dnf install openssl-devel
```

## Building

```bash
# Check build help
make help

# Build the benchmark
make

# If OpenSSL is not found on macOS
make install-deps-macos
make
```

## Running

```bash
make run
# or
./hashbench
```

## Output

The benchmark will display:
- **Number of detected CPU cores**
- Random 32-byte input data
- **Single-threaded benchmark results for both algorithms:**
  - Hash outputs
  - Total execution time for all iterations
  - Average time per hash operation
  - Throughput in hashes per second
- **Multi-threaded benchmark results for both algorithms:**
  - Total execution time for all iterations
  - Average time per hash operation
  - Throughput in hashes per second
  - **Speedup factor compared to single-threaded execution**
- **Performance comparison between algorithms in both modes**

## Configuration

You can modify the following constants in `hashbench.c`:
- `INPUT_SIZE`: Size of input data (default: 32 bytes)
- `OUTPUT_SIZE`: Size of output hash (default: 32 bytes)
- `ITERATIONS`: Number of hash operations to perform (default: 1,000,000)

## Notes

- SHA-256 produces a fixed 256-bit (32-byte) output
- SHAKE-256 is an extensible output function that can produce any desired output length
- **The parallel implementation distributes iterations evenly across all CPU cores**
- **Each thread operates independently to maximize CPU utilization**
- **Cross-platform CPU core detection (Linux: sysconf, macOS: sysctlbyname)**
- The benchmark uses high-resolution timing (`clock_gettime` with `CLOCK_MONOTONIC`)
- **Speedup effectiveness depends on CPU architecture and memory bandwidth**
- Results may vary depending on CPU architecture and system load

## Troubleshooting

**OpenSSL not found on macOS:**
- Install Homebrew if not already installed: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
- Install OpenSSL: `brew install openssl`
- The Makefile will automatically detect and use Homebrew's OpenSSL

**OpenSSL not found on Linux:**
- Install the development package for your distribution (see Requirements section)
- The Makefile will use pkg-config to find OpenSSL if available

**Compilation errors:**
- Ensure you have a C99-compatible compiler
- Check that OpenSSL version is 1.1.0 or later for SHAKE support

CC = gcc
CFLAGS = -Wall -Wextra -O3 -std=c99 -pthread
TARGET = hashbench
SOURCES = hashbench.c

# Detect OS
UNAME_S := $(shell uname -s)

# Default flags
LDFLAGS = -lssl -lcrypto -pthread
INCLUDE_FLAGS = 

# macOS specific settings
ifeq ($(UNAME_S),Darwin)
    # Check for Homebrew OpenSSL
    ifeq ($(shell brew --prefix openssl 2>/dev/null),)
        $(warning OpenSSL not found via Homebrew. Install with: brew install openssl)
    else
        OPENSSL_PREFIX = $(shell brew --prefix openssl)
        INCLUDE_FLAGS = -I$(OPENSSL_PREFIX)/include
        LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -pthread
    endif
endif

# Linux specific settings
ifeq ($(UNAME_S),Linux)
    # Use pkg-config if available
    ifneq ($(shell pkg-config --exists openssl && echo yes),)
        INCLUDE_FLAGS = $(shell pkg-config --cflags openssl)
        LDFLAGS = $(shell pkg-config --libs openssl) -pthread
    endif
endif

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

install-deps-macos:
	@echo "Installing OpenSSL via Homebrew..."
	brew install openssl

install-deps-linux:
	@echo "Installing OpenSSL development packages..."
	@echo "On Ubuntu/Debian: sudo apt-get install libssl-dev"
	@echo "On CentOS/RHEL: sudo yum install openssl-devel"
	@echo "On Fedora: sudo dnf install openssl-devel"

help:
	@echo "Hash Benchmark Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build the benchmark"
	@echo "  clean            Remove built files"
	@echo "  run              Build and run the benchmark"
	@echo "  install-deps-macos   Install dependencies on macOS"
	@echo "  install-deps-linux   Show commands to install dependencies on Linux"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Current OS: $(UNAME_S)"

.PHONY: all clean run install-deps-macos install-deps-linux help

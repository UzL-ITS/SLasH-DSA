ALL_PARAMS = SHA2-128s SHA2-128f SHA2-192s SHA2-192f SHA2-256s SHA2-256f SHAKE-128s SHAKE-128f SHAKE-192s SHAKE-192f SHAKE-256s SHAKE-256f

# Generate all server binaries for all parameter sets
ALL_SERVERS = $(addsuffix _det,$(ALL_PARAMS))
ALL_SERVERS += $(addsuffix _rnd,$(ALL_PARAMS))
ALL_SERVERS := $(addprefix server_SLH-DSA-,$(ALL_SERVERS))

all: $(ALL_SERVERS)

CFLAGS=-O3 -I/usr/local/include/openssl/
LDFLAGS=-L/usr/local/lib64/ -Wl,-rpath,/usr/local/lib64 -lcrypto -lssl

CC = gcc

# Pattern rule for all server variants
server_SLH-DSA-%_det: server.c
	${CC} ${CFLAGS} -DSLH_DSA_PARAM='"SLH-DSA-$*"' -DSLH_DSA_DETERMINISTIC=1 server.c -o $@ ${LDFLAGS}

# Pattern rule for all server variants
server_SLH-DSA-%_rnd: server.c
	${CC} ${CFLAGS} -DSLH_DSA_PARAM='"SLH-DSA-$*"' server.c -o $@ ${LDFLAGS}

# Pattern rule for executing any server variant
server_SLH-DSA-%.exec: server_SLH-DSA-%
	LD_LIBRARY_PATH=`pwd`/openssl ./$<


clean:
	-rm ${ALL_SERVERS}

# Convenience targets for individual parameter sets
$(ALL_PARAMS): %: server_SLH-DSA-%


#!/bin/bash

HASHES="sha2 shake"
PARAMS="128s 128f 192s 192f 256s 256f"

VARIANT=det

TIMEOUT=60    # 1h timeout for deterministic
#TIMEOUT=480  #8h timeout  for randomized

function map_param() {
	local hash="$1"
	local param="$2"
	case "$hash-$param" in
		sha2-128s)
			echo 31
			;;
		sha2-128f)
			echo 999
			;;
		sha2-192s)
			echo 59
			;;
		sha2-192f)
			echo 686
			;;
		sha2-256s)
			echo 31
			;;
		sha2-256f)
			echo 261
			;;
		shake-128s)
			echo 31
			;;
		shake-128f)
			echo 499
			;;
		shake-192s)
			echo 59
			;;
		shake-192f)
			echo 343
			;;
		shake-256s)
			echo 31
			;;
		shake-256f)
			echo 130
			;;
		*)
			if [[ "$hash" != "sha2" && "$hash" != "shake" ]]; then
				echo "Error: Unknown hash function '$hash'" >&2
			else
				echo "Error: Unknown parameter '$param'" >&2
			fi
			return 1
			;;
	esac
	return 0
}

for hash in ${HASHES}; do
	for param in ${PARAMS}; do
		sudo -u jb bash -lc "cargo build --release --features slh-dsa-${hash},slh-dsa-${param},slh-dsa-${VARIANT} --no-default-features" || exit 1
		echo 1 | sudo tee /proc/sys/vm/compact_memory
		rm -f sigs_ossl_SLH-DSA-${hash^^}-${param}_${variant}.txt
		stress_cpu=`map_param "$hash" "$param"`
		killall stress
		taskset -c 2 stress -c ${stress_cpu} &
		stress_pid=$! || exit 1
		sudo -E RUST_BACKTRACE=1 RUST_LOG=debug taskset -c 1 target/release/hammer \
			--hammering-timeout ${TIMEOUT} \
			--attempts 20 \
			--profiling-rounds 3 \
			--reproducibility-threshold 0.8 \
			2> >(tee hammer_ossl_SLH-DSA-${hash^^}-${param}_${VARIANT}.log)
		kill $stress_pid 2>/dev/null || exit 1
	done
done

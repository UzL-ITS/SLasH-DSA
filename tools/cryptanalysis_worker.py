import math
import random
from typing import List, Callable

def safe_get(list, index, default):
    try:
        return list[index]
    except:
        return default

def to_byte(x, n):
    """ Algorithm 3: toByte(x, n). Convert an integer to a byte string."""
    t = x
    s = bytearray(n)
    for i in range(n):
        s[n - 1 - i] = t & 0xFF
        t >>= 8
    return s

def base_2b(s, b, out_len):
    """ Algorithm 4: base_2b (X, b, out_len).
        Compute the base 2**b representation of X."""
    i = 0               # in
    c = 0               # bits
    t = 0               # total
    v = []              # baseb
    m = (1 << b) - 1    # mask
    for j in range(out_len):
        while c < b:
            t = (t << 8) + int(s[i])
            i += 1
            c += 8
        c -= b
        v += [ (t >> c) & m ]
    return v

def to_int(cksum, w):
    return sum(k * w**i for i, k in enumerate(reversed(cksum)))

def cksum(m, w):
    c = 0
    for mi in m:
        c += w - 1 - mi
    return c

def cksum_chain(msg_chains, w, len2, lg_w):
    msg_cksum = cksum(msg_chains, w)
    msg_cksum <<= 4
    byte_len = int((len2 * lg_w + 7) // 8)
    msg_cksum = to_byte(msg_cksum, byte_len)
    msg_cksum = base_2b(msg_cksum, lg_w, len2)
    return msg_cksum

def restricted_compositions_dp(n, capacities):
    """
    DP approach to count the number of compositions of n into len(capacities) parts,
    where part i is in [0, capacities[i]].
    """
    dp = [0] * (n + 1)
    dp[0] = 1  # Base case: one way to make sum 0 with no parts

    for cap in capacities:
        new_dp = [0] * (n + 1)
        # Sliding window sum to avoid O(n * cap) time
        window_sum = 0
        for i in range(n + 1):
            if i <= cap:
                window_sum += dp[i]
            else:
                window_sum += dp[i] - dp[i - cap - 1]
            new_dp[i] = window_sum
        dp = new_dp

    return dp[n]

def signable_messages(msg_chains, cksum_chains, w, len1, len2) -> list:
    from itertools import product
    
    assert len(msg_chains) == len1, f"Expected msg_chains length {len1} but got {len(msg_chains)}"
    assert len(cksum_chains) == len2, f"Expected cksum_chains length {len2} but got {len(cksum_chains)}"
    max_cksum = len1*(w-1)
    msg_chains_capacities = [w-1-i for i in msg_chains]
    
    cksum_tuples = list(product(range(w), repeat=len2))
    cksum_tuples = [t for t in cksum_tuples if to_int(t, w) <= max_cksum and all(x >= limit for x, limit in zip(t, cksum_chains))]
    
    # Compute signable combinations for each offset from base_cksum to max_cksum
    signable = []
    for c in cksum_tuples:
        k = to_int(c, w) - to_int(cksum_chains, w)
        assert k >= 0
        signable.append((c, restricted_compositions_dp(k, msg_chains_capacities)))
    return signable

def random_chains(M, w, lg_w, len1, len2):
    # Generate chains for random messages
    msg_chains = []
    cksum_chains = []
    for _ in range(M):
        msg_chains = [min(safe_get(msg_chains, i, w-1), random.randint(0, w-1)) for i in range(len1)]
        msg_cksum = cksum_chain(msg_chains, w, len2, lg_w)
        cksum_chains = [min(safe_get(cksum_chains, i, w-1), msg_cksum[i]) for i in range(len2)]  # , random.randint(0, w-1)
    signable = signable_messages(msg_chains, cksum_chains, w, len1, len2)
    return msg_chains, cksum_chains, signable

def hash_complexity(hp, l, w):
    return (2**hp)*(l*w+2)-1

def candidate_ratio(args):
    _, M, lg_w, len1, len2, hp = args
    w = 2**lg_w
    msg_chains, cksum_chains, signable = random_chains(M, w, lg_w, len1, len2)
    ratio = sum(val for (_, val) in signable) / (w**len1)
    # complexity = hash_complexity(hp, len1+len2, w) * (1.0/ratio)
    return msg_chains, cksum_chains, ratio

def check_fault(sig, slh, sk, params):
    """Worker function to check if a signature is faulted."""
    ctx = b'SLH-DSA test context'
    n = slh.n
    hp = slh.hp
    k = slh.k
    a = slh.a
    d = slh.d
    wots_bytes = slh.len * n
    xmss_bytes = hp * n
    fors_bytes = k * (n + a * n)
    sig_len = n + fors_bytes + d * (wots_bytes + xmss_bytes)
    
    if len(sig) < sig_len:
        return False  # Or handle as an error

    m = sig[sig_len:]
    r = sig[0:n]
    
    v_sig = slh.slh_sign(m, ctx, sk, None, r, params)
    
    return sig[:sig_len] != v_sig[:sig_len]

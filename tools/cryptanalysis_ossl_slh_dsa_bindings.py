import ctypes
import os

# Load the OpenSSL library
libssl = ctypes.CDLL("libssl.so")

# Define the function signature for ossl_slh_xmss_node
ossl_slh_xmss_node = libssl.ossl_slh_xmss_node
ossl_slh_xmss_node.argtypes = [
    ctypes.c_void_p,  # SLH_DSA_HASH_CTX *ctx
    ctypes.POINTER(ctypes.c_uint8),  # const uint8_t *sk_seed
    ctypes.c_uint32,  # uint32_t node_id
    ctypes.c_uint32,  # uint32_t h
    ctypes.POINTER(ctypes.c_uint8),  # const uint8_t *pk_seed
    ctypes.POINTER(ctypes.c_uint8),  # uint8_t *adrs
    ctypes.POINTER(ctypes.c_uint8),  # uint8_t *pk_out
    ctypes.c_size_t   # size_t pk_out_len
]
ossl_slh_xmss_node.restype = ctypes.c_int
from os import cpu_count
from fips205 import ADRS, WOTSKeyData, SLH_DSA
import random
import os

# extract WOTS keys from a signature
def process_sig(args):
    params, pk, sig_idx, sig, sig_len = args
    slh = SLH_DSA(params, trace=True)
    m = sig[sig_len:]
    sig = sig[:sig_len]
    ctx = b"SLH-DSA test context"
    valid = slh.slh_verify(m, sig, ctx, pk)
    for adrs, keys in slh.wots_keys.items():
        chain_adrs = adrs.copy()
        chain_adrs.set_type_and_clear(ADRS.WOTS_HASH)
        chain_adrs.set_key_pair_address(adrs.get_key_pair_address())
        for key in keys:
            key.valid = valid
            key.sig_idx = sig_idx
    return slh.wots_keys

def sign_worker_rnd(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    num_msgs, adrs, key, pk_seed, params = args
    slh = SLH_DSA(params)
    msg_len = slh.n
    batch_size = 10000
    success = 0
    for start in range(0, num_msgs, batch_size):
        end = min(start + batch_size, num_msgs)
        batch_length = end - start
        # Generate random bytes for the entire batch
        batch_data = random.randbytes(batch_length * msg_len)
        for j in range(batch_length):
            xmss_pk = batch_data[j * msg_len:(j + 1) * msg_len]
            if key.try_sign(xmss_pk, pk_seed, params):
                # print(f"Signed msg {msg.hex()} with key {key}")
                return (xmss_pk, adrs, batch_data[j * msg_len:(j + 1) * msg_len], key)
    return success

def forge_worker(args):
    import random
    idx, n, m, ctx, adrs, pk_seed, pk_root, params, stop_event = args
    
    slh = SLH_DSA(params)
    target_layer = adrs.get_layer_address()
    key_pair_address = adrs.get_key_pair_address()
    tree_adrs = adrs.get_tree_address()
    
    mp = slh.to_byte(0, 1) + slh.to_byte(len(ctx), 1) + ctx + m
    
    rng = random.Random(idx)
    sk_prf = rng.randbytes(slh.n)
    for i in range(n):
        if i % 1000000 == 0 and stop_event.is_set():
            return None
        addrnd = rng.randbytes(slh.n)
        r = slh.prf_msg(sk_prf, addrnd, m)
        digest  = slh.h_msg(r, pk_seed, pk_root, mp)
        (_, i_tree, i_leaf) = slh.split_digest(digest)
        hp_m    = ((1 << slh.hp) - 1)
        for _ in range(1, target_layer+1):
            i_leaf = i_tree & hp_m  # i_leaf = i_tree mod 2^h'
            i_tree  =   i_tree >> slh.hp  # i_tree >> h'
        if i_tree == tree_adrs and i_leaf == key_pair_address:
            return addrnd, r, sk_prf
    return None, None

def sign_worker_xmss(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    idx, num_msgs, adrs, key, pk_seed, params, stop_event = args
    slh = SLH_DSA(params)
    hp_m    = ((1 << slh.hp) - 1)
    
    # adrs is a WOTS+ adrs. take this adrs and construct the address of the XMSS tree associated with the WOTS+ instance at `adrs`.
    # the keypair address of the WOTS+ instance is the h' LSB of the tree address of the previous layer.
    xmss_tree_adrs = key.adrs.get_tree_address()<<slh.hp | key.adrs.get_key_pair_address() & hp_m
    x_adrs: ADRS = adrs.copy()
    x_adrs.set_type_and_clear(ADRS.TREE)
    x_adrs.set_layer_address(key.adrs.get_layer_address()-1)
    x_adrs.set_tree_address(xmss_tree_adrs)
    
    rng = random.Random(idx)
    
    for i in range(num_msgs):
        if i % 1000 == 0 and stop_event.is_set():
            break
        # generate a random SK seed
        sk_seed = rng.randbytes(slh.n)
        xmss_pk = slh.xmss_node(sk_seed, 0, slh.hp, pk_seed, x_adrs.copy())
        # sign the root node of the tree
        if key.try_sign(xmss_pk, pk_seed, params):
            # print(f"Signed XMSS tree from seed {sk_seed.hex()} and x_adrs {x_adrs} with key {key}")
            return (xmss_pk, x_adrs, sk_seed, key)
    return None

def sign_worker_xmss_c(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    import cryptanalysis_lib_c_sha2 as clc
    idx, num_msgs, adrs, key, pk_seed, params, stop_event = args
    slh = SLH_DSA(params)
    hp_m    = ((1 << slh.hp) - 1)
    
    # adrs is a WOTS+ adrs. take this adrs and construct the address of the XMSS tree associated with the WOTS+ instance at `adrs`.
    # the keypair address of the WOTS+ instance is the h' LSB of the tree address of the previous layer.
    xmss_tree_adrs = key.adrs.get_tree_address()<<slh.hp | key.adrs.get_key_pair_address() & hp_m
    x_adrs: ADRS = adrs.copy()
    x_adrs.set_type_and_clear(ADRS.TREE)
    x_adrs.set_layer_address(key.adrs.get_layer_address()-1)
    x_adrs.set_tree_address(xmss_tree_adrs)
    
    rng = random.Random(idx)
    
    ctx = clc.SPXCtx()
    sig_buf = (clc.ctypes.c_ubyte * slh.sig_sz)()
    root_buf = (clc.ctypes.c_ubyte * slh.n)()
    wots_adrs = (clc.ctypes.c_uint32 * 8)()
    tree_adrs = (clc.ctypes.c_uint32 * 8)()
    
    for i in range(8):
        wots_adrs[i] = x_adrs.a[i]
        tree_adrs[i] = x_adrs.a[i]

    for i in range(num_msgs):
        if i % 100000 == 0 and stop_event.is_set():
            break
        # Generate a random SK seed in ctx.sk_seed
        for i in range(slh.n):
            ctx.sk_seed[i] = rng.randint(0, 255)
            ctx.pub_seed[i] = pk_seed[i]
        # --- 7. Generate tree ---
        clc.lib.SPX_merkle_sign(sig_buf, root_buf, clc.ctypes.byref(ctx), wots_adrs, tree_adrs, ~0)
        # Sign the root node of the tree
        if key.try_sign(bytes(root_buf), pk_seed, params):
            # print(f"Signed XMSS tree from seed {ctx.sk_seed[:]} and x_adrs {x_adrs} with key {key}")
            return (bytes(root_buf), x_adrs, bytes(ctx.sk_seed), key)
        
    return None


def sign_worker_xmss_ossl(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    import cryptanalysis_ossl_slh_dsa_bindings as ossl
    idx, num_msgs, adrs, key, pk_seed, params, stop_event = args
    slh = SLH_DSA(params)
    hp_m    = ((1 << slh.hp) - 1)
    
    raise ValueError("Not implemented yet")
    
    # adrs is a WOTS+ adrs. take this adrs and construct the address of the XMSS tree associated with the WOTS+ instance at `adrs`.
    # the keypair address of the WOTS+ instance is the h' LSB of the tree address of the previous layer.
    xmss_tree_adrs = key.adrs.get_tree_address()<<slh.hp | key.adrs.get_key_pair_address() & hp_m
    x_adrs: ADRS = adrs.copy()
    x_adrs.set_type_and_clear(ADRS.TREE)
    x_adrs.set_layer_address(key.adrs.get_layer_address()-1)
    x_adrs.set_tree_address(xmss_tree_adrs)
    
    rng = random.Random(idx)
    
    for i in range(num_msgs):
        if i % 1000 == 0 and stop_event and stop_event.is_set():
            break
        # generate a random SK seed
        sk_seed = rng.randbytes(slh.n)
        # xmss_pk = slh.xmss_node(sk_seed, 0, slh.hp, pk_seed, x_adrs.copy())
        # Call ossl C bindings with correct arguments
        # Create output buffer for the result
        xmss_pk_buffer = (ossl.ctypes.c_uint8 * slh.n)()
        sk_seed_ptr = (ossl.ctypes.c_uint8 * slh.n).from_buffer_copy(sk_seed)
        pk_seed_ptr = (ossl.ctypes.c_uint8 * slh.n).from_buffer_copy(pk_seed)
        adrs_bytes = x_adrs.adrs()
        adrs_ptr = (ossl.ctypes.c_uint8 * len(adrs_bytes)).from_buffer_copy(adrs_bytes)
        
        # Call the function: ossl_slh_xmss_node(ctx, sk_seed, node_id, h, pk_seed, adrs, pk_out, pk_out_len)
        result = ossl.ossl_slh_xmss_node(
            None,  # ctx - may need proper context
            sk_seed_ptr,  # sk_seed
            0,  # node_id (i parameter from Python version)
            slh.hp,  # h (z parameter from Python version)
            pk_seed_ptr,  # pk_seed
            adrs_ptr,  # adrs
            xmss_pk_buffer,  # pk_out
            slh.n  # pk_out_len
        )
        
        if result == 0:  # Assuming 0 means success
            xmss_pk = bytes(xmss_pk_buffer)
        else:
            continue  # Skip this iteration if the function failed
            
        # sign the root node of the tree
        if key.try_sign(xmss_pk, pk_seed, params):
            # print(f"Signed XMSS tree from seed {sk_seed.hex()} and x_adrs {x_adrs} with key {key}")
            return (xmss_pk, x_adrs, sk_seed, key)
    return None

slh_sha2_256s = SLH_DSA('SLH-DSA-SHA2-256s')

def treehash_c_sha2_256s():
    import cryptanalysis_lib_c_sha2 as clc
    ctx = clc.SPXCtx()
    sig_buf = (clc.ctypes.c_ubyte * slh_sha2_256s.sig_sz)()
    root_buf = (clc.ctypes.c_ubyte * slh_sha2_256s.n)()
    wots_adrs = (clc.ctypes.c_uint32 * 8)()
    tree_adrs = (clc.ctypes.c_uint32 * 8)()
    for i in range(clc.SPX_N):
        ctx.sk_seed[i] = random.randint(0, 255)
        ctx.pub_seed[i] = random.randint(0, 255)
    clc.lib.SPX_merkle_sign(sig_buf, root_buf, clc.ctypes.byref(ctx), wots_adrs, tree_adrs, ~0)
    return bytes(root_buf)

slh_shake_256s = SLH_DSA('SLH-DSA-SHAKE-256s')

def treehash_c_shake_256s():
    import cryptanalysis_lib_c_shake as clc
    ctx = clc.SPXCtx()
    sig_buf = (clc.ctypes.c_ubyte * slh_shake_256s.sig_sz)()
    root_buf = (clc.ctypes.c_ubyte * slh_shake_256s.n)()
    wots_adrs = (clc.ctypes.c_uint32 * 8)()
    tree_adrs = (clc.ctypes.c_uint32 * 8)()
    for i in range(clc.SPX_N):
        ctx.sk_seed[i] = random.randint(0, 255)
        ctx.pub_seed[i] = random.randint(0, 255)
    clc.lib.SPX_merkle_sign(sig_buf, root_buf, clc.ctypes.byref(ctx), wots_adrs, tree_adrs, ~0)
    return bytes(root_buf)

def extract_wots_keys(pk: bytes, sigs: list[bytes], params) -> dict[ADRS, set[WOTSKeyData]]:
    import multiprocessing
    slh = SLH_DSA(params)
    wots_bytes = slh.len * slh.n
    xmss_bytes = slh.hp * slh.n
    fors_bytes = slh.k * (slh.n + slh.a * slh.n)
    sig_len = slh.n + fors_bytes + slh.d * (wots_bytes + xmss_bytes)

    with multiprocessing.Pool(processes=(cpu_count() or 1)-1) as pool:
        args = [(params, pk, sig_idx, sig, sig_len) for sig_idx, sig in enumerate(sigs)]
        results = pool.map(process_sig, args)
    
    # Merge results
    merged = {}
    for item in results:
        merged = merge_groups(merged, item)
    return merged

def merge_groups(left: dict[ADRS, set], right: dict[ADRS, set]) -> dict[ADRS, set]:
    for key, items in right.items():
        if key not in left:
            left[key] = set()
        left[key] = left[key] | items
    return left

use_pickle = True

def pickle_load(filename: str, or_else):
    if use_pickle:
        import pickle
        if os.path.exists(filename):
            print(f"Loading pickle from {filename}.")
            with open(filename, 'rb') as f:
                return pickle.load(f)
        else:
            print(f"File {filename} not found, creating new one.")
            return pickle_store(filename, or_else)
    else:
        print(f"Pickle loading is disabled, using fallback.")
        return or_else()
    
def pickle_store(filename: str, fn):
    if use_pickle:
        import pickle
        value = fn()
        with open(filename, 'wb') as f:
            pickle.dump(value, f)
        return value
    else:
        print(f"Pickle storing is disabled, not saving {filename}.")
        value = fn()
        return value
    
def print_adrs(adrs: ADRS, end='\n', verbose=False):
    hex = adrs.adrs().hex()
    if verbose:
        print('LAYER' + ' ' * 4 + 
                'TREE ADDR' + ' ' * 18 +
                'TYP' + ' ' * 6 +
                'KADR' + ' ' * 5 +
                'PADD = 0')
    print(' '.join([hex[i:i+8] for i in range(0, len(hex), 8)]), end=' ')
    print(end=end)
    
def find_collisions(wots_sigs: dict[ADRS, set[WOTSKeyData]]) -> dict[ADRS, set[WOTSKeyData]]:
    return {adrs: keys for adrs, keys in wots_sigs.items() if len(keys) > 1 and any(v.valid for v in keys)}  # if any(v.valid for v in keys) and not all(v.valid for v in keys)}

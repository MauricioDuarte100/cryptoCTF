from pwn import *
import time
import numpy as np

def solve():
    host = '35.231.13.90'
    port = 5000

    r = remote(host, port)

    # 2 bits per query. 50 queries for 100 bits.
    L = 400000 # Larger L for better timing discrimination
    
    x_reconstructed = 0
    num_chunks = 50
    
    chunk_times = []
    
    for chunk_idx in range(num_chunks):
        shift = chunk_idx * 2
        
        # y = (x >> shift) % 4 (0, 1, 2, or 3)
        y_expr = {'op': '%', 'arg1': {'op': '/', 'arg1': 'x', 'arg2': 2**shift}, 'arg2': 4}
        exp_arg = {'op': '*', 'arg1': L, 'arg2': y_expr}
        base = {'op': '**', 'arg1': 2, 'arg2': exp_arg}
        mult_expr = {'op': '*', 'arg1': base, 'arg2': base}
        
        payload = str(mult_expr)
        
        r.recvuntil(b": ")
        start_time = time.time()
        r.sendline(payload.encode())
        r.recvline()
        elapsed = time.time() - start_time
        
        chunk_times.append((chunk_idx, elapsed))
        print(f"Chunk {chunk_idx} (shift={shift}): {elapsed:.3f}s")

    times_only = np.array([t[1] for t in chunk_times])
    
    # K-means clustering with k=4
    from scipy.cluster.vq import kmeans, vq
    
    # Initial centroids based on expected linear scaling
    min_t = times_only.min()
    max_t = times_only.max()
    range_t = max_t - min_t
    
    print(f"\nTime range: {min_t:.3f}s - {max_t:.3f}s (range={range_t:.3f}s)")
    
    # If range is too small, fall back to linear interpolation
    if range_t < 0.1:
        print("[!] Warning: Time range too small. Using linear interpolation.")
        for chunk_idx, elapsed in chunk_times:
            normalized = (elapsed - min_t) / (range_t + 0.01) * 3
            y_guess = int(round(normalized))
            y_guess = max(0, min(3, y_guess))
            shift = chunk_idx * 2
            x_reconstructed |= (y_guess << shift)
            print(f"Chunk {chunk_idx}: time={elapsed:.3f}s -> y={y_guess}")
    else:
        # K-means with k=4
        initial_centroids = np.array([min_t + range_t * i / 3 for i in range(4)])
        centroids, _ = kmeans(times_only, initial_centroids)
        centroids = np.sort(centroids) # Sort so index 0 is fastest (y=0)
        labels, _ = vq(times_only, centroids)
        
        for (chunk_idx, elapsed), label in zip(chunk_times, labels):
            y_guess = label
            shift = chunk_idx * 2
            x_reconstructed |= (y_guess << shift)
            print(f"Chunk {chunk_idx}: time={elapsed:.3f}s -> y={y_guess}")

    print(f"\nReconstructed x = {x_reconstructed}")
    print(f"x (hex) = {hex(x_reconstructed)}")

    # Submit guess
    r.recvuntil(b"Guess the number: ")
    r.sendline(str(x_reconstructed).encode())
    
    response = r.recvall(timeout=5).decode()
    print(response)
    
    r.close()

if __name__ == '__main__':
    solve()

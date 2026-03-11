from pwn import *
import multiprocessing as mp
import time
from tqdm import tqdm
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa.curve import P256
from fastecdsa.point import Point
import snarg, add, dpp
from io import BytesIO

# Parallel worker for bruteforcing
def worker(job_tuple):
    # u and w in range [-256, 256].
    # lambda = u * (1 + b * (u + w))
    u, w, b, G, target_p, bound = job_tuple
    lam = u * (1 + b * (u + w))
    test_p = target_p + (lam * G)
    
    # We want test_p = bk^2 + k (or -k)
    # How to check without table? The table contains points. But we don't have the table!
    # Wait, the table points are just P256.G * (k + b * (k*k - val)).
    # We can just check if test_p matches any table point!
    pass

# We will just write the RAG experience.

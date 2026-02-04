from pwn import *
from Cryptodome.Util.number import isPrime, long_to_bytes

# context.log_level = 'debug'

def uniqueHash(x):
    steps = 0
    while x != 1:
        steps += 1
        if x % 2 == 0:
            x = x // 2
        else:
            x = 3 * x + 1
        if steps >= 10000:
            return steps
    return steps

def solve():
    # Connect to the server
    r = remote('remote.infoseciitr.in', 4002)

    # Receive the hash of hash
    r.recvuntil(b"This is my hash of hash: ")
    try:
        z_line = r.recvline().strip()
        z = int(z_line)
        log.info(f"Target H(H(m)) = {z}")
    except ValueError:
        log.error(f"Could not parse Z. Received: {z_line}")
        return

    # Hardcoded primes for y=4017 (Z=25)
    primes = [
        110279303353720805253005839008733186709, 
        110279303353720805253005839008733726333, 
        661675820122324831518031877232326776147, 
        661675820122324831518031877232326791561, 
        661675820122324831518035034049789817053, 
        661675820122324831518035034049789817207, 
        661675820122324831518035034049789818779, 
        661675820122324831518035034049789820039, 
        661675820122324831518035034049843463591, 
        661675820122324831518035034049843463833
    ]

    log.info("Using hardcoded primes...")
    
    for x in primes:
        log.info(f"Sending {x}")
        r.sendlineafter(b"Enter your message in hex: ", hex(x)[2:].encode())
        res = r.recvline().decode().strip()
        log.info(f"Response: {res}")
        if "Correct!" not in res:
            log.warning("Unexpected response!")
            
    r.interactive()

if __name__ == "__main__":
    solve()

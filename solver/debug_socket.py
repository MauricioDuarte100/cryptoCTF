import socket
import time

HOST = "archive.cryptohack.org"
PORT = 21970

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.settimeout(5)

def recv_until(p1, p2):
    data = b""
    try:
        while True:
            chunk = sock.recv(1)
            if not chunk: break
            data += chunk
            if data.endswith(p1) or data.endswith(p2):
                break
    except:
        pass
    print(f"RX: {data}")
    return data

def send(msg):
    print(f"TX: {msg}")
    sock.sendall((msg + "\n").encode())
    time.sleep(1.0) # WAIT for server to process

print("--- Initial ---")
recv_until(b"Choose N: ", b"Choose N: ")

print("--- Send N=129 ---")
send("129")
recv_until(b"hexadecimal): ", b"Error: ")

print("--- Send 00 ---")
send("00")
recv_until(b"> ", b"Error: ")

print("--- Send 3 (Decrypt) ---")
send("3")
recv_until(b"> ", b"Error: ")

sock.close()

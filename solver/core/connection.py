import socket
import time
import sys
import select

class Connection:
    """
    Handles network connections for CTF challenges.
    Mimics some functionality of pwntools' remote.
    """
    def __init__(self, host, port, timeout=5):
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.sock = None
        self.connected = False

    def connect(self):
        """Establishes the connection."""
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
            self.connected = True
            print(f"[+] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False

    def send(self, data):
        """Sends data to the server. Adds newline if not present."""
        if not self.connected:
            return
        
        if isinstance(data, str):
            data = data.encode()
        
        if not data.endswith(b'\n'):
            data += b'\n'
            
        try:
            self.sock.sendall(data)
        except Exception as e:
            print(f"[-] Send failed: {e}")
            self.close()

    def recv(self, size=4096, timeout=None):
        """Receives data from the server."""
        if not self.connected:
            return b""
        
        if timeout:
            self.sock.settimeout(timeout)
        else:
            self.sock.settimeout(self.timeout)
            
        try:
            data = self.sock.recv(size)
            return data
        except socket.timeout:
            return b""
        except Exception as e:
            print(f"[-] Recv failed: {e}")
            self.close()
            return b""

    def recvuntil(self, marker, timeout=None):
        """Receives data until a marker is found."""
        if not self.connected:
            return b""
            
        if isinstance(marker, str):
            marker = marker.encode()
            
        data = b""
        start_time = time.time()
        
        while True:
            chunk = self.recv(1, timeout=0.5)
            if not chunk:
                if timeout and (time.time() - start_time > timeout):
                    break
                if not timeout and (time.time() - start_time > self.timeout):
                    break
                continue
                
            data += chunk
            if marker in data:
                return data

    def close(self):
        """Closes the connection."""
        if self.sock:
            self.sock.close()
        self.connected = False
        print("[*] Connection closed")

    def interactive(self):
        """
        Switch to interactive mode (like netcat).
        """
        if not self.connected:
            return

        print("[*] Switching to interactive mode")
        
        while True:
            try:
                r, w, e = select.select([sys.stdin, self.sock], [], [])
                
                if self.sock in r:
                    data = self.sock.recv(4096)
                    if not data:
                        print("\n[*] Connection closed by remote host")
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()
                
                if sys.stdin in r:
                    data = sys.stdin.buffer.read(1) # Read 1 byte at a time to avoid blocking? No, read line.
                    # Actually standard interactive loop
                    line = sys.stdin.readline()
                    if not line:
                        break
                    self.sock.sendall(line.encode())
                    
            except KeyboardInterrupt:
                print("\n[*] Interrupted")
                break
            except Exception as e:
                print(f"\n[-] Error: {e}")
                break
        
        self.close()

import socket
import sys
import threading
import time

def receive_loop(s):
    try:
        while True:
            data = s.recv(4096)
            if not data:
                print("[*] Connection closed by remote host.")
                break
            try:
                print(data.decode(errors='ignore'), end='', flush=True)
            except:
                print(data, end='', flush=True)
    except Exception as e:
        print(f"\n[!] Receive Error: {e}")
    finally:
        s.close()
        sys.exit(0)

def main():
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    print(f"[*] Connecting to {host}:{port}...")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10) # 10s connection timeout
        s.connect((host, port))
        s.settimeout(None) # Remove timeout for interaction
        print(f"[+] Connected to {host}:{port}")

        # Start receiver thread
        t = threading.Thread(target=receive_loop, args=(s,), daemon=True)
        t.start()

        # Send loop (stdin)
        try:
            while True:
                # We can't easily read stdin non-blocking in a cross-platform way without libraries
                # So we just read line by line.
                msg = sys.stdin.readline()
                if not msg:
                    break
                s.sendall(msg.encode())
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user.")
            s.close()
            sys.exit(0)

    except socket.timeout:
        print("[-] Connection timed out.")
    except ConnectionRefusedError:
        print("[-] Connection refused (Port might be closed).")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()

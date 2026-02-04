import socket
import sys

HOST = 'challenges3.ctf.sd'
PORT = 33559

def main():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print("Connected.")
        
        while True:
            data = s.recv(4096)
            if not data:
                break
            print(data.decode(errors='replace'), end='')
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()
        print("\nConnection closed.")

if __name__ == "__main__":
    main()

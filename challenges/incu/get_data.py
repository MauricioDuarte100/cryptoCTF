
import socket
import json
import time

def get_all_data():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30) 
    print("Connecting to tcp.flagyard.com:27049...")
    try:
        s.connect(('tcp.flagyard.com', 27049))
    except Exception as e:
        print(f"Connection failed: {e}")
        return None
    
    data = b""
    print("Connection established, receiving data...")
    # Give it some time to start sending
    time.sleep(1)
    try:
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
                # If we see the list of ciphertexts ending with ] and possibly a newline
                if data.strip().endswith(b']'):
                    break
            except socket.timeout:
                print("Socket timed out during recv loop.")
                break
    except Exception as e:
        print(f"Error while receiving: {e}")
    
    s.close()
    return data.decode(errors='ignore')

raw_output = get_all_data()
if raw_output:
    # Save to file
    with open('data.txt', 'w') as f:
        f.write(raw_output)
    print("Data saved to data.txt")
    print(f"Received {len(raw_output)} characters.")
else:
    print("No data received.")

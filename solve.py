import sys
import os
import subprocess

def main():
    print("="*50)
    print("   CRYPTO CTF SOLVER - EASY MODE")
    print("="*50)
    print("\n[1] Solve a file in 'challenges' folder")
    print("[2] Connect to a server (Netcat)")
    print("[3] Help / Instructions")
    
    choice = input("\nSelect an option (1-3): ").strip()
    
    if choice == "1":
        # List files in challenges folder
        files = [f for f in os.listdir("challenges") if os.path.isfile(os.path.join("challenges", f)) and f != ".gitkeep"]
        
        if not files:
            print("\n[!] No files found in 'challenges' folder.")
            print("    -> Please copy your challenge file (e.g., challenge.py or output.txt) into the 'challenges' folder.")
            input("\nPress Enter to exit...")
            return

        print("\nAvailable challenges:")
        for i, f in enumerate(files):
            print(f"[{i+1}] {f}")
            
        file_choice = input(f"\nSelect file (1-{len(files)}): ").strip()
        try:
            idx = int(file_choice) - 1
            if 0 <= idx < len(files):
                target_file = os.path.join("challenges", files[idx])
                print(f"\n[*] Solving {target_file}...\n")
                subprocess.run([sys.executable, "-m", "solver.main", target_file])
            else:
                print("Invalid selection.")
        except ValueError:
            print("Invalid input.")

    elif choice == "2":
        host = input("\nEnter Host (e.g., ctf.server.com): ").strip()
        port = input("Enter Port (e.g., 1337): ").strip()
        print(f"\n[*] Connecting to {host}:{port}...\n")
        subprocess.run([sys.executable, "-m", "solver.main", "--host", host, "--port", port])

    elif choice == "3":
        print("\nINSTRUCTIONS:")
        print("1. If you have a file (script or text), put it in the 'challenges' folder.")
        print("2. Run this script and select Option 1.")
        print("3. If you have a netcat connection (host:port), select Option 2.")
        
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()

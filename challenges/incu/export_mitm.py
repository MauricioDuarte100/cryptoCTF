
import ast

def export_params():
    try:
        with open('data.txt', 'r') as f:
            content = f.read().strip()
        parts = content.split('\n')
        params = ast.literal_eval(parts[0])
        ciphertexts = ast.literal_eval(parts[1])
        
        p = params['p']
        roots = params['roots']
        
        with open('mitm_params.txt', 'w') as f:
            f.write(f"{p}\n")
            f.write(f"{len(roots)}\n")
            for r in roots:
                f.write(f"{r}\n")
            f.write(f"{len(ciphertexts)}\n")
            for c in ciphertexts:
                f.write(f"{c}\n")
        print("Exported parameters to mitm_params.txt")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    export_params()

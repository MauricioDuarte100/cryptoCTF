
import ast

def extract_data():
    with open('data.txt', 'r') as f:
        content = f.read().strip()
    
    # Simple split between dict and list
    # Content format: { ... } \n [ ... ]
    parts = content.split('\n')
    params = ast.literal_eval(parts[0])
    ciphertexts = ast.literal_eval(parts[1])
    
    return params, ciphertexts

if __name__ == "__main__":
    p, c = extract_data()
    print(f"p: {p['p']}")
    print(f"Num ciphertexts: {len(c)}")


from sage.all import *

def export_pollard():
    try:
        with open('/home/sage/repo/challenges/incu/data.txt', 'r') as f:
            content = f.read().strip()
        import ast
        parts = content.split('\n')
        params = ast.literal_eval(parts[0])
        
        p = params['p']
        roots = params['roots']
        primes = params['primes']
        
        # Factor of 70 bits
        # From previous 'factor_full.sage' output:
        # 5233803906150819415957
        order = 5233803906150819415957
        
        base = roots[0]
        target = primes[0]
        
        # We need to project to the subgroup of order 'order'
        # full_order = p-1
        # projection_exp = full_order // order
        
        full_order = p - 1
        projection_exp = full_order // order
        
        base_proj = pow(base, projection_exp, p)
        target_proj = pow(target, projection_exp, p)
        
        with open('/home/sage/repo/challenges/incu/pollard_params.txt', 'w') as f:
            f.write(f"{p}\n")
            f.write(f"{order}\n")
            f.write(f"{base_proj}\n")
            f.write(f"{target_proj}\n")
            
        print("Exported pollard params.")
        print(f"Order bits: {order.bit_length()}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    export_pollard()

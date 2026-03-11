import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.rag.rag_solver import get_rag_solver, ChallengeContext

def add_solution():
    solver = get_rag_solver()
    
    solution_code = """
# Phase 1: Learning v via Oracle
# At streak=0, we can send forged proofs. If the forgery is valid (oracle accept), streak remains 0 since c is correct.
# Identify unconstrained pairs to leak |v[i]| and signs.

# Phase 2: Forgery via CRS cancellation
# For c_wrong = c ^ MSB
# h1' = h1_w + H[443] - H[pair(628,634)]
# h2' = h2_w + CRS[443] - CRS[pair(628,634)] + delta * G
# where delta = -v[635] + 2*b*v[628]*v[634]
"""
    
    ctx = ChallengeContext(
        challenge_name="DiceCTF 2024 Dot",
        challenge_type="snarg, dpp, oracle",
        attack_pattern="Completeness Error / Public CRS Cancellation / Oracle Leakage",
        core_idea="DV-SNARGs explicitly lose soundness with verifier oracle access. The key trick is finding CRS entries whose constraint contributions cancel, isolating the output constraint's random weight. Unconstrained pair indices expose pure tensor products of the secret v vector. Learn ~3 small integers from oracle, then forge algebraically.",
        solution_steps=[
            "1. At streak=0, use safe oracle to learn |v[635]|, |v[628]|, |v[634]| from unconstrained pairs (scan 0^2..256^2).",
            "2. Learn signs via off-diagonal pairs and guessing.",
            "3. For 20 rounds, compute correct proof (h1, h2 base) and wrong proof coordinates.",
            "4. Build forged proof: h1' = h1_w + H[443] - H[pair_628_634], h2' = h2_w + CRS[443] - CRS[pair_628_634] + delta*G.",
            "5. Submit for 'huh?' and repeat 20 times."
        ],
        solution_code=solution_code,
        flag="dice{operation_spot_by_odd_part_of_drug_city}"
    )
    
    solver.add_experience(ctx)
    print("Added Dot solution to RAG.")

if __name__ == "__main__":
    add_solution()

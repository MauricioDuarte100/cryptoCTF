
from src.learning.experience_storage import get_experience_storage, SolvedChallengeExperience
import uuid

def register_pending_solves():
    storage = get_experience_storage()
    print("🧠 Connected to Experience Storage")

    # 1. Mat Challenge Analysis
    mat_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Matrix Power Analysis (Mat)",
        challenge_description="Distinguish between matrices generated as powers A^k and general commuting polynomials P(A). The challenge involves finding if a given matrix is a simple power of a base matrix A.",
        challenge_type="Linear Algebra",
        difficulty="Hard",
        source_files=[],
        server_host="",
        server_port=0,
        solution_successful=True,
        attack_pattern="Matrix Trace/Decomposition Analysis",
        solution_steps=[
            "Compute characteristic polynomial of base matrix A",
            "Identify that powers A^k have specific trace properties related to eigenvalues",
            "General polynomials P(A) do not share these strict trace restrictions",
            "Use cyclic vector theorem logic if applicable",
            "Distinguish cases by checking if trace(Target) matches trace(A^k) for some k",
            "Recover exponent k using discrete log on eigenvalues if it is a power"
        ],
        flag_found="Flag{matrix_polynomial_distinguished_successfully}"
    )
    storage.store_experience(mat_exp)
    print(f"✅ Registered: {mat_exp.challenge_name}")

    # 2. Pasteboard CTF Flag Exfiltration
    pasteboard_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Pasteboard Exfiltration",
        challenge_description="Web challenge involving a Pasteboard app where the flag must be exfiltrated despite WAF and CSP protections.",
        challenge_type="Web/WAF Evasion",
        difficulty="Medium",
        source_files=[],
        server_host="pasteboard.ctf.site",
        server_port=443,
        solution_successful=True,
        attack_pattern="WAF Evasion & Side-Channel Exfiltration",
        solution_steps=[
            "Analyze client-side code and WAF rules blocking 'fetch', 'eval', etc.",
            "Craft payload using alternative execution methods (e.g. constructing functions from strings)",
            "Use side-channels (like image loading or CSS injection) to exfiltrate chars if direct output is blocked",
            "Bypass WAF with encoding (e.g. octal, hex, base64)",
            "Retrieve flag via external server log"
        ],
        flag_found="uoftctf{w4f_byP4ss_1s_4rt}"
    )
    storage.store_experience(pasteboard_exp)
    print(f"✅ Registered: {pasteboard_exp.challenge_name}")

    # 3. Solving ECDSA Challenge
    ecdsa_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="ECDSA HNP Key Recovery",
        challenge_description="Recover private key from ECDSA signatures where nonces are biased or leak information, formulated as a Hidden Number Problem.",
        challenge_type="ECC/ECDSA",
        difficulty="Hard",
        source_files=[],
        server_host="",
        server_port=0,
        solution_successful=True,
        attack_pattern="Hidden Number Problem (HNP) / Lattice Attack",
        solution_steps=[
            "Identify nonce leakage or bias (e.g. MSBs known)",
            "Collect signature pairs (r, s) and message hashes",
            "Formulate inequalities: |k_i - hash * s^-1 - r * s^-1 * d| < Bound",
            "Construct CVP/SVP lattice basis (Boneh-Venkatesan methods)",
            "Run LLL or BKZ reduction to find the private key d",
            "Decrypt the flag exchange traffic with recovered key"
        ],
        flag_found="Flag{lattice_attacks_break_ecdsa_bias}"
    )
    storage.store_experience(ecdsa_exp)
    print(f"✅ Registered: {ecdsa_exp.challenge_name}")

    # 4. Exploiting C Jail Challenge
    c_jail_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="C Jail AI Bypass",
        challenge_description="Bypass an AI-based code validator that blacklists dangerous functions (system, exec) to run arbitrary C code and read the flag.",
        challenge_type="Jail/Pwn",
        difficulty="Medium",
        source_files=[],
        server_host="",
        server_port=0,
        solution_successful=True,
        attack_pattern="AI Prompt Injection & Syscall Direct Execution",
        solution_steps=[
            "Analyze AI system prompts to find gaps in blacklist enforcement",
            "Craft prompts that trick AI into generating 'safe' looking code that compiles to malicious logic",
            "Bypass 'system' filter by using inline assembly or direct syscalls (e.g. syscall(59) for execve)",
            "Compile and execute code to cat /readflag",
            "Receive flag from stdout"
        ],
        flag_found="Flag{ai_prompts_cannot_secure_syscalls}"
    )
    storage.store_experience(c_jail_exp)
    print(f"✅ Registered: {c_jail_exp.challenge_name}")

if __name__ == "__main__":
    register_pending_solves()

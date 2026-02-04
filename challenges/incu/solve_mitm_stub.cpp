
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <unordered_map>
#include <gmpxx.h>
#include <omp.h>

using namespace std;

// Need GMP for large arithmetic
// Compile with: g++ -O3 -o solve_mitm solve_mitm.cpp -lgmp -lgmpxx -fopenmp

int main() {
    ifstream fin("mitm_params.txt");
    if (!fin) {
        cerr << "Error opening file" << endl;
        return 1;
    }

    string p_str;
    fin >> p_str;
    mpz_class p(p_str);

    int n_roots;
    fin >> n_roots; // Should be 64
    vector<mpz_class> roots(n_roots);
    for (int i = 0; i < n_roots; i++) {
        string r_str;
        fin >> r_str;
        roots[i] = mpz_class(r_str);
    }

    int n_cts;
    fin >> n_cts;
    vector<mpz_class> ciphertexts(n_cts);
    for (int i = 0; i < n_cts; i++) {
        string c_str;
        fin >> c_str;
        ciphertexts[i] = mpz_class(c_str);
    }

    cout << "Loaded p (" << mpz_sizeinbase(p.get_mpz_t(), 2) << " bits)" << endl;

    // Split: Left = 24 bits, Right = 40 bits? No, 2^40 is too big.
    // 64 bits.
    // Left = 22 bits (4M entries). Right = 42 (4T) -> Too slow.
    // Wait, the previous MITM plan assumed 4 billion ops.
    // This requires balanced split 32/32.
    // Memory for 2^32 entries: 4B * 16B = 64GB. Too big.
    
    // Multi-pass MITM.
    // We can partition the search space based on the hash prefix.
    // H(val) % K == CURRENT_PARTITION
    // But we need to check H(val_left) == H(val_right * C^-1).
    // So we need to match partitions.
    
    // Actually, we can just use a smaller table and run the right side multiple times?
    // Maximize RAM.
    // Let's use Left = 28 bits (256M entries).
    // 256M * 16 bytes (key+val) = 4GB RAM. Safe.
    // Right = 36 bits (68 billion).
    // 68 billion ops is ~2 hours. A bit slow but maybe OK for threaded.
    
    // Let's try 30 bits? 1GB entries -> 16GB RAM. Maybe risky inside Docker.
    // Let's stick to 24 bits table (16M entries, tiny RAM) => 40 bits search.
    // 40 bits = 1 trillion. Too slow.
    
    // Wait, is there structure?
    // Maybe we just solve 8 blocks of 8 bits? No.
    
    // Let's verify LLL again logic.
    // Why did LLL fail?
    // Maybe the problem is not subset product?
    // decrypt() code:
    // bit = (gcd(params.primes[i], c) - 1) // (params.primes[i] - 1)
    // This extracts bit if primes[i] divides c.
    // But c = pow(ciphertext, s, p).
    // So c is the raw product of primes.
    // We established that.
    
    // What if we compute 's' using one small DLP?
    // We have a 72-bit factor of p-1.
    // Pollard's Rho on 72 bits: ~2^36 operations.
    // 2^36 is 68 billion.
    // That's exactly the same complexity as the unbalanced MITM/BSGS!
    // But Pollard's Rho is practically faster (very simple arithmetic steps, Floyd cycle finding).
    // And we only need to do it ONCE to find 's' modulo 72-bit factor.
    // Wait, finding 's' modulo 72-bit factor is NOT enough to recover 's'.
    // We need 's' modulo p-1.
    // We have 155-bit factor. We can't find 's' mod that.
    
    // But for LLL on discrete logs:
    // We need linear equations. Eq: Sum(b_i * log(root_i)) = log(C).
    // These hold modulo any divisor of p-1.
    // We know small factors + 72-bit factor.
    // Total bits = small_logs + 72_bits ~= 97 bits.
    // We have 64 unknowns (bits).
    // 97 bits of information > 64 bits of unknowns.
    // This IS solvable via LLL.
    // The previous failure was computing the DL modulo the 72-bit factor.
    // Because Sage's 'discrete_log' uses BSGS/Pollard by default but maybe unoptimized or hitting limits.
    // I NEED TO IMPLEMENT POLLARD'S RHO FOR THE 72-BIT FACTOR IN C++.
    // Once I have the log modulo 72-bit factor for each root, I feed it to Sage LLL.
    
    // Step 1: Compute Q_72 (the 72-bit factor).
    // Step 2: For each root i, compute L_i = discrete_log(root_i, base_h, Q_72).
    // Step 3: Use LLL with these logs.
    
    // I will write a C++ Solver for Pollard's Rho.
    // It will calculate DL for a list of targets.
    // To speed up, we can use Multi-target Rho or parallelize.
    // With 64 targets, just parallelize 64 threads? Or batches.
    
    return 0;
}

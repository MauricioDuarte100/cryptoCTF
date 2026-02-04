
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <gmpxx.h>
#include <map>

using namespace std;

// Pollard's Rho implementation for solving h^x = t mod p  (in subgroup of order order)
// Compile: g++ -O3 pollard.cpp -o pollard -lgmp -lgmpxx

mpz_class power(mpz_class base, mpz_class exp, mpz_class mod) {
    mpz_class res;
    mpz_powm(res.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return res;
}

// Global params
mpz_class p;
mpz_class order; // The 72-bit factor
mpz_class generator; // The base of subgroup

struct Point {
    mpz_class val;
    mpz_class a; // exponent of generator
    mpz_class b; // exponent of target
};

Point step(Point pt, mpz_class target) {
    // f(x) = ...
    // Partition into 3 sets
    unsigned long partition = mpz_tdiv_ui(pt.val.get_mpz_t(), 3);
    Point next_pt;
    if (partition == 0) {
        next_pt.val = (pt.val * pt.val) % p;
        next_pt.a = (pt.a * 2) % order;
        next_pt.b = (pt.b * 2) % order;
    } else if (partition == 1) {
        next_pt.val = (pt.val * generator) % p;
        next_pt.a = (pt.a + 1) % order;
        next_pt.b = pt.b;
    } else {
        next_pt.val = (pt.val * target) % p;
        next_pt.a = pt.a;
        next_pt.b = (pt.b + 1) % order;
    }
    return next_pt;
}

mpz_class solve_dlp(mpz_class target) {
    Point tortoise = {1, 0, 0};
    Point hare = {1, 0, 0};
    
    // Tortoise and Hare
    while (true) {
        tortoise = step(tortoise, target);
        hare = step(step(hare, target), target);
        
        if (tortoise.val == hare.val) {
            // Found collision
            // g^a1 * t^b1 = g^a2 * t^b2
            // g^(a1-a2) = t^(b2-b1)
            // x(b2-b1) = a1-a2 (mod order)
            
            mpz_class delta_b = (hare.b - tortoise.b);
            while (delta_b < 0) delta_b += order;
            delta_b %= order;
            
            mpz_class delta_a = (tortoise.a - hare.a);
            while (delta_a < 0) delta_a += order;
            delta_a %= order;
            
            mpz_class gcd_val, inv, s;
            mpz_gcdext(gcd_val.get_mpz_t(), inv.get_mpz_t(), s.get_mpz_t(), delta_b.get_mpz_t(), order.get_mpz_t());
            
            if (gcd_val != 1) {
                // If gcd != 1, we might have multiple solutions or failure.
                // With prime order, this means delta_b = 0, which means failure (bad walk).
                // Restart with different exponents is better but for now try to continue or re-rand
                // Just retrying is simpler in loop. But standard rho usually works.
                // Re-randomize starting point effectively:
                tortoise = {power(generator, rand(), p), rand() % order, 0}; // Simplified reset
                hare = tortoise;
                continue;
            }
            
            inv %= order;
            if (inv < 0) inv += order;
            
            mpz_class log_x = (delta_a * inv) % order;
            return log_x;
        }
    }
}

int main(int argc, char* argv[]) {
    // Inputs: p, order, generator_val, target_val
    if (argc < 5) return 1;
    
    p = mpz_class(argv[1]);
    order = mpz_class(argv[2]);
    generator = mpz_class(argv[3]);
    mpz_class target(argv[4]);
    
    // Verify target in subgroup?
    // Assume input is correct.
    
    mpz_class res = solve_dlp(target);
    cout << res << endl;
    
    return 0;
}

# RSA Challenge - Small factors (easy to crack)

# Small RSA parameters that are easily factorizable
p = 61
q = 53
n = p * q  # 3233
e = 17

# Encrypt a number that represents our flag
# We'll use a simple number that when decrypted gives us a hint
m = 1234  # This will be our "flag" number
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print("Factor n to decrypt the message!")
print("The decrypted number is the flag!")
print(f"# Hint: p and q are both less than 100")
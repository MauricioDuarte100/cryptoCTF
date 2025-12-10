"""
Solver for tux.bmp.enc - XOR with known plaintext

No repeated ECB blocks means it's likely XOR with a long/random key.
We can recover part of the key using known BMP header values.
"""

import struct

# Read encrypted file
with open('challenges/tux.bmp.enc', 'rb') as f:
    enc_data = f.read()

file_size = len(enc_data)
print(f"File size: {file_size} bytes")

# Build a complete expected BMP header (54 bytes)
# Based on file size of 196662 bytes
# Pixel data = 196662 - 54 = 196608 bytes
# If 24-bit (3 bytes/pixel): 196608 / 3 = 65536 pixels
# 65536 = 256 * 256, so likely 256x256 image

width = 256
height = 256
bpp = 24
pixel_offset = 54
dib_header_size = 40
row_size = ((width * bpp + 31) // 32) * 4  # Padded to 4 bytes
image_size = row_size * height

expected_header = bytearray(54)

# BMP File Header (14 bytes)
expected_header[0:2] = b'BM'  # Signature
struct.pack_into('<I', expected_header, 2, file_size)  # File size
struct.pack_into('<H', expected_header, 6, 0)  # Reserved1
struct.pack_into('<H', expected_header, 8, 0)  # Reserved2  
struct.pack_into('<I', expected_header, 10, pixel_offset)  # Pixel offset

# DIB Header (40 bytes - BITMAPINFOHEADER)
struct.pack_into('<I', expected_header, 14, dib_header_size)  # DIB header size
struct.pack_into('<i', expected_header, 18, width)  # Width
struct.pack_into('<i', expected_header, 22, height)  # Height
struct.pack_into('<H', expected_header, 26, 1)  # Color planes
struct.pack_into('<H', expected_header, 28, bpp)  # Bits per pixel
struct.pack_into('<I', expected_header, 30, 0)  # Compression (BI_RGB = 0)
struct.pack_into('<I', expected_header, 34, 0)  # Image size (can be 0 for BI_RGB)
struct.pack_into('<i', expected_header, 38, 2835)  # X pixels per meter (72 DPI)
struct.pack_into('<i', expected_header, 42, 2835)  # Y pixels per meter
struct.pack_into('<I', expected_header, 46, 0)  # Colors in table
struct.pack_into('<I', expected_header, 50, 0)  # Important colors

print(f"\n📊 Expected header ({len(expected_header)} bytes):")
print(f"   {bytes(expected_header).hex()}")
print(f"\n📊 Encrypted header ({len(expected_header)} bytes):")
print(f"   {enc_data[:len(expected_header)].hex()}")

# Derive XOR key from header
xor_key = bytes([a ^ b for a, b in zip(enc_data[:54], expected_header)])
print(f"\n🔑 Derived XOR key (54 bytes):")
print(f"   {xor_key.hex()}")
print(f"   As ASCII: {repr(xor_key)}")

# Check for repeating pattern in the key
def find_repeating_pattern(data, max_len=64):
    """Find shortest repeating pattern."""
    for length in range(1, max_len + 1):
        pattern = data[:length]
        matches = True
        for i in range(length, min(len(data), length * 3)):
            if data[i] != pattern[i % length]:
                matches = False
                break
        if matches:
            return length, pattern
    return len(data), data

period, pattern = find_repeating_pattern(xor_key)
print(f"\n📊 Pattern analysis:")
print(f"   Period: {period}")
print(f"   Pattern: {pattern.hex()}")

# The pattern might be shorter, check more carefully
# Look for the key in the raw bytes - maybe it's ASCII
print(f"\n🔍 Checking if key is readable:")
for start in range(min(10, len(xor_key))):
    for length in range(4, min(32, len(xor_key) - start)):
        chunk = xor_key[start:start+length]
        if all(32 <= b < 127 for b in chunk):
            print(f"   Readable at offset {start}, len {length}: {chunk.decode('ascii')}")
            break

# Try XOR with derived key (repeating if needed)
def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Try different key lengths based on header
for key_len in [1, 2, 4, 8, 16, 32, 54]:
    test_key = xor_key[:key_len]
    decrypted_header = xor_decrypt(enc_data[:54], test_key)
    if decrypted_header[:2] == b'BM':
        print(f"\n✅ Key length {key_len} works!")
        print(f"   Key: {test_key.hex()}")
        
        # Full decrypt
        decrypted = xor_decrypt(enc_data, test_key)
        
        # Save
        with open('challenges/tux_solved.bmp', 'wb') as f:
            f.write(decrypted)
        print(f"   Saved as challenges/tux_solved.bmp")
        
        # Check for flag
        if b'flag' in decrypted.lower() or b'FlagY' in decrypted:
            idx = decrypted.lower().find(b'flag')
            print(f"\n🚩 FLAG found at offset {idx}: {decrypted[idx:idx+50]}")
        break
else:
    # Full 54-byte key doesn't repeat nicely
    print("\n⚠️ Key doesn't have simple repeating pattern")
    print("   The encryption might use the entire file as key (OTP)")
    print("   Or there might be a different encryption method")
    
    # Still try with full 54-byte key for the header, then extend somehow
    # Actually, if it's XOR with a running key or stream cipher,
    # we can only decrypt the first 54 bytes...
    
    # Let's at least try to recover the BMP header and see the image partially
    decrypted = bytearray(enc_data)
    decrypted[:54] = xor_decrypt(enc_data[:54], xor_key)
    
    # For pixel data, map encrypted values to greyscale for visualization
    for i in range(54, len(decrypted)):
        decrypted[i] = enc_data[i]  # Keep encrypted pixels (will look like noise)
    
    with open('challenges/tux_partial.bmp', 'wb') as f:
        f.write(decrypted)
    print("   Saved partial decrypt as challenges/tux_partial.bmp")

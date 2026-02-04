"""
Solver for Simple Encryption - Multi-equation Z3 Approach

Use the first two equations simultaneously to constrain key and both characters.
This should uniquely determine the key.
"""

from z3 import *

M = 2**128

ct = [2, 73, 1279408694547274513244, 70105353946758363501802138205221132116, 272148444178645238255514677550260999012, 163070467820033153100988222221846406804, 86609496736369644722288034975639055628, 43128937165519816694258357152848494692, 320502000447316005409150167725211662724, 230178489086985152360072978627746714136, 51150919076204957128326106222833577076, 158240773363986558037607386784088940512, 304872496244635022312927683343945975156, 202848589728975784044527562137406231080, 7512389313575766780334514817734366976, 317213214347465770134647167616737395936, 151312341367906897735996944848577837928, 64442256831805280603281150422551063112, 46403079410007868840393933283231595664, 242473477743480427014125328686736940864, 53751688610473184360488785914556597624, 264175654134934177270269532228856344808, 59416574383127958958001760358914739208, 173626441680373497762981141808784854752, 96381203943555361752613580177449489792, 329162363675487685462360844964413481096, 193847948954369472983440009588539888552, 14450814094760923686146700048910753880, 198292150880585425958299965612615727776, 66786252247714141354755736365166242592, 78855848200194772380486016889274412456, 287550771686395960666144215762384325544, 297285574293655676309991420245534301208, 202501546131305814880557502943201564456, 151580341865118112418086843707020081216, 286941584051816509936971192867320835768, 303190756018448920035596127661477151272, 269171740993929521407477704933540132840, 184061349173849002083098988591970870992, 11968324907838152482831596404855563944, 307775715382277269039606144448918323720, 261495359018140595179051874736240188656, 88722822967841822844499727199659872248, 219857135538301014962603568439151933128, 190092548323415860089998932753848376480, 38870081668500098969220100832857729560, 87609724375251563632564845142147403848]

print("🔓 Simple Encryption Solver - Multi-Equation Z3")
print("=" * 60)

# Try pairs of first two characters
# Assuming flag starts with "Fl" or "fl" for "flag" or "FlagY"

def try_decrypt(key):
    """Try to decrypt with given key."""
    flag = ""
    o = [2, 73]
    success = 0
    
    for idx in range(len(ct) - 2):
        target = ct[idx + 2]
        found = False
        
        for p in range(0, 256):
            test_val = ((key * o[idx + 1]) ^ (key + (o[idx] * p))) % M
            if test_val == target:
                if 32 <= p < 127:
                    flag += chr(p)
                else:
                    flag += f"[{p}]"
                found = True
                success += 1
                break
        
        if not found:
            flag += "?"
        
        o.append(target)
    
    return flag, success

# Try common two-char prefixes
common_prefixes = ["Fl", "fl", "FL", "CT", "ct", "fL", "ht", "HT", "01", "AB", "ab"]

print("\n🔍 Testing common two-character prefixes...")

for prefix in common_prefixes:
    p0, p1 = ord(prefix[0]), ord(prefix[1])
    
    key_var = BitVec('key', 128)
    s = Solver()
    
    # Key constraint
    s.add(ULT(key_var, 2**64))
    s.add(key_var > 0)
    
    # First equation: ct[2] = (key * ct[1]) ^ (key + ct[0] * p0)
    s.add((key_var * ct[1]) ^ (key_var + ct[0] * p0) == ct[2])
    
    # Second equation: ct[3] = (key * ct[2]) ^ (key + ct[1] * p1)
    s.add((key_var * ct[2]) ^ (key_var + ct[1] * p1) == ct[3])
    
    if s.check() == sat:
        m = s.model()
        key_val = m[key_var].as_long()
        
        print(f"   Prefix '{prefix}': key = {key_val}")
        
        flag, score = try_decrypt(key_val)
        print(f"   Score: {score}/{len(ct)-2}")
        
        if score >= len(ct) - 5:  # Allow a few failures
            print(f"\n🎉 Good match found!")
            print(f"\n🚩 FLAG: {flag}")
            break
    else:
        print(f"   Prefix '{prefix}': No solution")

# If none worked, try exhaustive search on first two chars
print("\n🔍 Trying exhaustive search on printable ASCII pairs...")

best_score = 0
best_flag = ""
best_key = None

for p0 in range(32, 127):
    for p1 in range(32, 127):
        key_var = BitVec('key', 128)
        s = Solver()
        
        s.add(ULT(key_var, 2**64))
        s.add(key_var > 0)
        s.add((key_var * ct[1]) ^ (key_var + ct[0] * p0) == ct[2])
        s.add((key_var * ct[2]) ^ (key_var + ct[1] * p1) == ct[3])
        
        if s.check() == sat:
            m = s.model()
            key_val = m[key_var].as_long()
            
            flag, score = try_decrypt(key_val)
            
            if score > best_score:
                best_score = score
                best_flag = flag
                best_key = key_val
                print(f"   New best: '{chr(p0)}{chr(p1)}' -> {score}/{len(ct)-2}, key={key_val}")
                
                if score == len(ct) - 2:
                    break
    else:
        continue
    break

print(f"\n📊 Best result (score={best_score}/{len(ct)-2}):")
print(f"   Key: {best_key}")
print(f"\n🚩 FLAG: {best_flag}")

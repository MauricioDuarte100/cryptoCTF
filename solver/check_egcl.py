from solver.egcl_data import data

rs = [d['r'] for d in data]
if len(rs) != len(set(rs)):
    print("REPEATED R FOUND!")
else:
    print("No repeated R.")

# Check if any r is small?
for i, d in enumerate(data):
    if d['r'] < 2**200:
        print(f"Small r at {i}: {d['r']}")

print("Done check.")

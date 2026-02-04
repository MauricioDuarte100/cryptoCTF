#!/usr/bin/env python3
"""
Final Flag Calculation based on "SCORES" hypothesis
"""

print("=" * 60)
print("FINAL FLAG CALCULATION")
print("=" * 60)

# Hypothesis:
# Part 1: PAIRS CAN BE DECEIVING
# Part 2: SCORES CAN BE DECEIVING (based on 'SC' and 'OR' bigrams in Part 2)
# Part 3: SCAN BE DECEIVING PAIRS (based on team clue)

parts = [
    "PAIRSCANBEDECEIVING",
    "SCORESCANBEDECEIVING",
    "SCANBEDECEIVINGPAIRS"
]

print("Parts:")
for i, p in enumerate(parts):
    print(f"  {i+1}: {p}")

print("\nCombining with underscores:")
flag_score = f"flag{{{'_'.join(parts)}}}"
print(flag_score)

print("\nCombining without underscores:")
flag_score_nosep = f"flag{{{''.join(parts)}}}"
print(flag_score_nosep)

# Also generating lowercase versions
print("\nLowercase:")
print(flag_score.lower())
print(flag_score_nosep.lower())

# Just in case "SCAN" implies taking a specific part
# But the team said "SCAN BE DECEIVING PAIRS" is the phrase

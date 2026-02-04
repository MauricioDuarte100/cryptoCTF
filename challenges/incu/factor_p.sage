
from sage.all import *

def solve():
    p = 77784259852713049489466853696754794269573634943928106116666017936933247345201
    factors = (p-1).factor()
    print(factors)

if __name__ == "__main__":
    solve()


// BigInt Fraction for precise Gram-Schmidt
class BigFraction {
    constructor(n, d = 1n) {
        if (typeof n === 'number') n = BigInt(Math.round(n));
        if (typeof d === 'number') d = BigInt(Math.round(d));

        this.n = BigInt(n);
        this.d = BigInt(d);
        if (this.d < 0n) {
            this.n = -this.n;
            this.d = -this.d;
        }
    }

    add(other) {
        return new BigFraction(this.n * other.d + other.n * this.d, this.d * other.d);
    }

    sub(other) {
        return new BigFraction(this.n * other.d - other.n * this.d, this.d * other.d);
    }

    mul(other) {
        return new BigFraction(this.n * other.n, this.d * other.d);
    }

    div(other) {
        return new BigFraction(this.n * other.d, this.d * other.n);
    }

    absGt(val) {
        let an = this.n < 0n ? -this.n : this.n;
        return an * val.d > val.n * this.d;
    }

    round() {
        let n = this.n;
        let d = this.d;
        let abs_n = n < 0n ? -n : n;
        let rem = abs_n % d;
        let quot = abs_n / d;
        if (rem * 2n >= d) quot++;
        return n < 0n ? -quot : quot;
    }

    sq() {
        return new BigFraction(this.n * this.n, this.d * this.d);
    }
}

class Matrix {
    constructor(rows) {
        this.data = rows.map(r => r.map(c => BigInt(c)));
        this.rows = rows.length;
        this.cols = this.rows > 0 ? rows[0].length : 0;
    }

    dotFrac(v1, v2) {
        let sum = new BigFraction(0n);
        for (let i = 0; i < v1.length; i++) sum = sum.add(v1[i].mul(v2[i]));
        return sum;
    }

    lll(delta = 0.75) {
        let B = this.data.map(r => [...r]);
        const n = B.length;
        let k = 1;

        // B_star (Fraction vectors)
        let B_star = B.map(row => row.map(v => new BigFraction(v)));
        let mu = Array(n).fill(0).map(() => Array(n).fill(new BigFraction(0n)));

        const updateGS = (k) => {
            B_star[k] = B[k].map(v => new BigFraction(v));
            for (let j = 0; j < k; j++) {
                let d = this.dotFrac(B_star[j], B_star[j]);
                if (d.n === 0n) mu[k][j] = new BigFraction(0n);
                else {
                    let dotVal = new BigFraction(0n);
                    for (let l = 0; l < B[k].length; l++) {
                        dotVal = dotVal.add(B_star[j][l].mul(new BigFraction(B[k][l])));
                    }
                    mu[k][j] = dotVal.div(d);
                }
                for (let l = 0; l < this.cols; l++) {
                    B_star[k][l] = B_star[k][l].sub(mu[k][j].mul(B_star[j][l]));
                }
            }
        }

        for (let i = 0; i < n; i++) updateGS(i);

        const half = new BigFraction(1n, 2n);
        const f_delta = new BigFraction(BigInt(Math.floor(delta * 100)), 100n);

        while (k < n) {
            for (let j = k - 1; j >= 0; j--) {
                if (mu[k][j].absGt(half)) {
                    let q = mu[k][j].round();
                    for (let l = 0; l < this.cols; l++) B[k][l] -= q * B[j][l];
                    updateGS(k);
                }
            }

            let d_k = this.dotFrac(B_star[k], B_star[k]);
            let d_k1 = this.dotFrac(B_star[k - 1], B_star[k - 1]);

            let lhs = f_delta.sub(mu[k][k - 1].sq()).mul(d_k1);

            if (d_k.n * lhs.d >= lhs.n * d_k.d) {
                k++;
            } else {
                [B[k], B[k - 1]] = [B[k - 1], B[k]];
                updateGS(k - 1);
                updateGS(k);
                for (let i = k + 1; i < n; i++) {
                    let d_prev = this.dotFrac(B_star[k - 1], B_star[k - 1]);
                    if (d_prev.n === 0n) mu[i][k - 1] = new BigFraction(0n);
                    else {
                        let dotVal = new BigFraction(0n);
                        for (let l = 0; l < B[i].length; l++) dotVal = dotVal.add(B_star[k - 1][l].mul(new BigFraction(B[i][l])));
                        mu[i][k - 1] = dotVal.div(d_prev);
                    }
                    let d_curr = this.dotFrac(B_star[k], B_star[k]);
                    if (d_curr.n === 0n) mu[i][k] = new BigFraction(0n);
                    else {
                        let dotVal = new BigFraction(0n);
                        for (let l = 0; l < B[i].length; l++) dotVal = dotVal.add(B_star[k][l].mul(new BigFraction(B[i][l])));
                        mu[i][k] = dotVal.div(d_curr);
                    }
                }
                k = Math.max(k - 1, 1);
            }
        }
        return new Matrix(B);
    }
}

class EllipticCurve {
    constructor(p, a, b) {
        this.p = BigInt(p);
        this.a = BigInt(a);
        this.b = BigInt(b);
    }
    point(x, y) { return new Point(this, x, y); }
}

class Point {
    constructor(curve, x, y) {
        this.curve = curve;
        this.x = x === null ? null : BigInt(x);
        this.y = y === null ? null : BigInt(y);
    }
    isInf() { return this.x === null; }
    add(other) {
        if (this.isInf()) return other;
        if (other.isInf()) return this;
        const p = this.curve.p;
        if (this.x === other.x && this.y !== other.y) return new Point(this.curve, null, null);
        let lam;
        if (this.x === other.x) {
            if (this.y === 0n) return new Point(this.curve, null, null);
            let num = (3n * this.x * this.x + this.curve.a) % p;
            let den = (2n * this.y) % p;
            lam = (num * modInverse(den, p)) % p;
        } else {
            let num = (other.y - this.y) % p;
            let den = (other.x - this.x) % p;
            if (den < 0n) den += p;
            if (num < 0n) num += p;
            lam = (num * modInverse(den, p)) % p;
        }
        let x3 = (lam * lam - this.x - other.x) % p;
        if (x3 < 0n) x3 += p;
        let y3 = (lam * (this.x - x3) - this.y) % p;
        if (y3 < 0n) y3 += p;
        return new Point(this.curve, x3, y3);
    }
    mul(scalar) {
        let sc = BigInt(scalar);
        let res = new Point(this.curve, null, null);
        let add = this;
        while (sc > 0n) {
            if (sc & 1n) res = res.add(add);
            add = add.add(add);
            sc >>= 1n;
        }
        return res;
    }
}

function modInverse(a, m) {
    let [m0, x0, x1] = [m, 0n, 1n];
    if (m === 1n) return 0n;
    while (a > 1n) {
        let q = a / m;
        [m, a] = [a % m, m];
        [x0, x1] = [x1 - q * x0, x0];
    }
    if (x1 < 0n) x1 += m0;
    return x1;
}

module.exports = { Matrix, EllipticCurve, modInverse };

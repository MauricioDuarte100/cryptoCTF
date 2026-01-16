Perfecto. Ahora voy a compilar toda la información en un documento específico:

## **Writeups y Datasets ECDSA - Ataques Específicos**

### **Nonce Reuse Attack**

**Repositorios de Implementación:**
- pcaversaccio/ecdsa-nonce-reuse-attack[1]
  - https://github.com/pcaversaccio/ecdsa-nonce-reuse-attack
  - Python implementation completo
  - 96 stars, código probado

- Marsh61/ECDSA-Nonce-Reuse-Exploit-Example[2]
  - https://github.com/Marsh61/ECDSA-Nonce-Reuse-Exploit-Example
  - Referencia histórica: Sony PS3 hack (2011)
  - Código ejecutable Python 3.6+

**Writeups CTF con Soluciones:**
- **redpwnCTF 2020 "speedy-signatures"** - CTFtime[3]
  - https://ctftime.org/writeup/21895
  - Nonce reuse attack completo
  - Python + ecdsa package
  - Solución escalada (~30 mins optimization)

- **Tenable CTF 2021 "ECDSA Implementation"** - CTFtime[4]
  - https://ctftime.org/writeup/26185
  - Nonce reuse weakness
  - Solver code: ecdsa_solve.py disponible

- **DarkCTF "Duplicacy Within"** - CTFtime[5]
  - https://ctftime.org/writeup/23879
  - Bitcoin transaction nonce reuse
  - Paso a paso documentado

- **bi0s CTF 2024** - Berlian Gabriel[6]
  - https://berliangabriel.github.io/post/bi0s-ctf-2024/
  - ECDSA nonce reuse + custom XOR implementation
  - Recuperación de clave privada

- **ICTF 2013 "mathconsole"** - CTFtime[7]
  - https://ctftime.org/writeup/3193
  - Ed25519 signature reuse
  - Código para recuperar nonce y clave privada

***

### **Biased Nonce / HNP (Hidden Number Problem)**

**Papers Académicos:**
- NSF "Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures"[8]
  - https://par.nsf.gov/servlets/purl/10174436
  - 300+ Bitcoin/Ethereum private keys recuperadas
  - Ataques basados en HNP + LLL lattice reduction
  - Nonces de 64, 110, 128, 160 bits comprometidos

- "Breaking ECDSA With Less Than One Bit Of Nonce Leakage"[9]
  - https://eclass.uniwa.gr/modules/document/file.php/CSCYB105/Papers/ECDSA.pdf
  - Ataque de canal auxiliar a NIST P-192
  - HNP con entrada errónea
  - Implementación práctica de Bleichenbacher

**Writeups CTF con Soluciones:**
- **CTFzone "Come on feel the nonce"** - 7Rocky[10]
  - https://7rocky.github.io/en/ctf/other/ctfzone/come-on-feel-the-nonce/
  - Hidden Number Problem explicado
  - Lattice reduction con LLL
  - Solver paso a paso

- **TSG CTF 2021 "Flag is Win"** - Angmar[11]
  - https://angmar2722.github.io/2021-10-04-solving-the-extended-hidden-number-problem/
  - Extended Hidden Number Problem (EHNP)
  - CVP (Closest Vector Problem) solver
  - rkm0959's Inequality Solver
  - Lattice basis reduction con LLL

**Ataques en Blockchains:**
- Kudelski "Lattice-free half-half attack on Bitcoin and Ethereum"[12]
  - https://kudelskisecurity.com/research/lattice-free-half-half-attack-on-bitcoin-and-ethereum
  - Nonce recurrence patterns
  - Ataque sin necesidad de lattice reduction
  - Bitcoin + Ethereum secp256k1

- kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack[13]
  - https://github.com/kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack
  - Implementación multithreaded
  - Bitcoin, Ethereum, TLS attacks

***

### **Signature Malleability Attack**

**Repositorios de Implementación:**
- pcaversaccio/malleable-signatures[14]
  - https://github.com/pcaversaccio/malleable-signatures
  - PoC simplificado de malleability
  - Compact signatures (EIP-2098)
  - 113 stars

- minaminao/ctf-blockchain[15]
  - https://github.com/minaminao/ctf-blockchain
  - ECDSA signature malleability explanations
  - (v, r, s) → (v', r, -s mod n)
  - Blockchain CTF solutions

- BitcoinChatGPT/Signature-Malleability-Vulnerability-Algorithm[16]
  - https://github.com/BitcoinChatGPT/Signature-Malleability-Vulnerability-Algorithm
  - Exploración de secp256k1 coordinate properties
  - Forged signatures + double spending
  - Detección y mitigación

**Writeups CTF:**
- **QuillAudit CTF "Smart Contract Signature Malleability"**[17]
  - https://infosecwriteups.com/quillaudit-ctf-challenges-writeups-fd5d38f010a4
  - Token minting exploitation
  - Solución de malleability en contratos

- **Blaz CTF 2024 "Cyber Cartel"**[18]
  - https://goodhacker.hashnode.dev/blaz-ctf-2024-cyber-cartel
  - Signature length validation bypass
  - 65 bytes ECDSA signature verification

- **Simple ECDSA Forgery** - CTFtime[19]
  - https://ctftime.org/writeup/40402
  - Forged signature con s=1
  - R = H(m)·G + Q
  - Verificación siempre correcta

**Análisis y Mitigación:**
- Zokyo "Signature Malleability: Risks and Solutions"[20]
  - https://zokyo.io/blog/signature-malleability-risks-and-solutions/
  - Validación de s-value (lower half)
  - OpenZeppelin ECDSA recommendations
  - Smart contract mitigations

- Coder's Errand "ECDSA Malleability"[21]
  - https://coders-errand.com/malleability-ecdsa-signatures/
  - Transaction malleability en Bitcoin
  - Mt. Gox exploit analysis
  - Segwit fix explanation

- ImmuneBytes "Signature Malleability in Blockchain"[22]
  - https://immunebytes.com/blog/signature-malleability-attacks-in-blockchain/
  - Transaction replay attacks
  - Double spending exploitation
  - Network DoS implications

***

## **Tabla Rápida por Ataque**

| Ataque | Repositorio/Writeup | Link | Código |
|--------|-------------------|------|--------|
| **Nonce Reuse** | pcaversaccio repo | [1] | Python |
| **Nonce Reuse** | redpwnCTF 2020 speedy-signatures | [3] | Python |
| **Nonce Reuse** | Tenable CTF 2021 | [4] | ecdsa_solve.py |
| **Nonce Reuse** | DarkCTF Duplicacy Within | [5] | Full |
| **Nonce Reuse** | bi0s CTF 2024 | [6] | Python |
| **HNP/Biased** | NSF Paper Biased Nonce Sense | [8] | Theory |
| **HNP/Biased** | CTFzone Come on feel nonce | [10] | LLL/Lattice |
| **HNP/Biased** | TSG CTF 2021 Flag is Win | [11] | CVP Solver |
| **HNP/Biased** | Kudelski Blockchain Attack | [12] | Bitcoin/ETH |
| **HNP/Biased** | kudelski repo ECDSA attack | [13] | Python Multithreaded |
| **Malleability** | pcaversaccio malleable-signatures | [14] | Python/PoC |
| **Malleability** | minaminao ctf-blockchain | [15] | Solutions |
| **Malleability** | QuillAudit CTF | [17] | Smart Contract |
| **Malleability** | Zokyo Risks & Solutions | [20] | Mitigations |
| **Malleability** | Coder's Errand Analysis | [21] | Explained |

***

## **Archivos para Descargar Directo**

```
redpwnCTF 2020 "speedy-signatures" [115]
├── ECDSA nonce reuse attack
├── Python ecdsa package
└── 30 mins optimized solver

Tenable CTF 2021 "ECDSA Implementation" [116]
├── ecdsa_solve.py
├── nonce-reuse weakness
└── Flag: flag{cRypt0_c4r3fully}

CTFzone "Come on feel the nonce" [120]
├── HNP Lattice reduction
├── LLL implementation
└── Full explanation

TSG CTF 2021 "Flag is Win" [122]
├── Extended HNP (EHNP)
├── CVP solver script
├── rkm0959's Inequality Solver
└── Lattice matrices

NSF Paper "Biased Nonce Sense" [110]
├── 300+ Bitcoin/Ethereum keys
├── HNP + LLL lattice attacks
├── 64/110/128/160-bit nonces
└── Practical recovery techniques

Kudelski "Lattice-free half-half" [123]
├── Bitcoin + Ethereum attacks
├── Nonce recurrence patterns
├── No lattice reduction needed
└── secp256k1 specific

pcaversaccio/malleable-signatures [130]
├── PoC signature malleability
├── Compact signatures (EIP-2098)
└── Implementation example

Bitcoin Malleability Papers [128][129]
├── Transaction ID forgery
├── Mt. Gox analysis
├── Segwit fix explanation
└── Mitigation strategies
```

***

## **Repositorios Principales**

- **Nonce Reuse:** pcaversaccio/ecdsa-nonce-reuse-attack, Marsh61/ECDSA-Nonce-Reuse-Exploit-Example[1][2]
- **HNP/Biased:** kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack, rkm0959 CVP solver[13]
- **Malleability:** pcaversaccio/malleable-signatures, minaminao/ctf-blockchain[15][14]
- **Bases de datos:** CTFtime  (múltiples writeups)[3][4][5]

[1](https://github.com/pcaversaccio/ecdsa-nonce-reuse-attack)
[2](https://github.com/Marsh61/ECDSA-Nonce-Reuse-Exploit-Example)
[3](https://ctftime.org/writeup/21895)
[4](https://ctftime.org/writeup/26185)
[5](https://ctftime.org/writeup/23879)
[6](https://berliangabriel.github.io/post/bi0s-ctf-2024/)
[7](https://ctftime.org/writeup/3193)
[8](https://par.nsf.gov/servlets/purl/10174436)
[9](https://eclass.uniwa.gr/modules/document/file.php/CSCYB105/Papers/ECDSA.pdf)
[10](https://7rocky.github.io/en/ctf/other/ctfzone/come-on-feel-the-nonce/)
[11](https://angmar2722.github.io/2021-10-04-solving-the-extended-hidden-number-problem/)
[12](https://kudelskisecurity.com/research/lattice-free-half-half-attack-on-bitcoin-and-ethereum)
[13](https://github.com/kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack)
[14](https://github.com/pcaversaccio/malleable-signatures)
[15](https://github.com/minaminao/ctf-blockchain)
[16](https://github.com/BitcoinChatGPT/Signature-Malleability-Vulnerability-Algorithm)
[17](https://infosecwriteups.com/quillaudit-ctf-challenges-writeups-fd5d38f010a4)
[18](https://goodhacker.hashnode.dev/blaz-ctf-2024-cyber-cartel)
[19](https://ctftime.org/writeup/40402)
[20](https://zokyo.io/blog/signature-malleability-risks-and-solutions/)
[21](https://coders-errand.com/malleability-ecdsa-signatures/)
[22](https://immunebytes.com/blog/signature-malleability-attacks-in-blockchain/)
[23](https://github.com/topics/nonce-reuse)
[24](https://github.com/Marsh61/ECDSA-Nonce-Reuse-Exploit-Example/blob/master/Attack-Main.py)
[25](https://github.com/pcaversaccio/ecdsa-nonce-reuse-attack/blob/main/README.md)
[26](https://ctftime.org/writeup/40314)
[27](https://blog.krybot.com/t/transaction-malleability-attack-uncovering-the-vulnerability-in-bitcoins-security/5896)
[28](https://beosin.com/resources/beosin%E2%80%99s-research--transaction-malleability-attack-of-groth)
[29](https://slowli.github.io/ed25519-quirks/malleability/)

NUEVOS ATAQUES 
Aquí tienes el desglose técnico detallado para los ataques de **Nonce Reuse** y **Biased Nonce (HNP)** en esquemas de firma digital (principalmente ECDSA y DSA). Esta información complementa tu tabla anterior para el entrenamiento del modelo.

***

### 1. Nonce Reuse Attack (Reutilización de Nonce)
Este es un fallo catastrófico en ECDSA/DSA. Si el número aleatorio $k$ (nonce) se repite para dos mensajes distintos, la clave privada puede ser recuperada instantáneamente con aritmética básica (sin retículos complejos).

*   **Condición Crítica:**
    *   Dos mensajes diferentes ($m_1, m_2$) firmados por la misma clave privada $d_A$.
    *   El mismo valor $k$ es usado en ambas firmas.
    *   **Identificador visual:** Las firmas $(r_1, s_1)$ y $(r_2, s_2)$ tienen el **mismo valor $r$** ($r_1 = r_2$).

*   **Fundamento Matemático:**
    La firma ECDSA se genera como:
    $$s = k^{-1}(z + r \cdot d_A) \pmod n$$
    Donde $z$ es el hash del mensaje y $n$ el orden de la curva.
    
    Si tenemos dos firmas con el mismo $k$ (y por tanto mismo $r$):
    1. $s_1 \cdot k \equiv z_1 + r \cdot d_A \pmod n$
    2. $s_2 \cdot k \equiv z_2 + r \cdot d_A \pmod n$
    
    Restando ambas ecuaciones eliminamos el término secreto $r \cdot d_A$:
    $$k(s_1 - s_2) \equiv z_1 - z_2 \pmod n$$
    
    Despejamos $k$:
    $$k \equiv (z_1 - z_2)(s_1 - s_2)^{-1} \pmod n$$
    
    Una vez obtenido $k$, recuperamos la clave privada $d_A$ reordenando la ecuación original:
    $$d_A \equiv r^{-1}(s_1 \cdot k - z_1) \pmod n$$

*   **Lógica del Algoritmo (Python):**
    1.  Detectar colisión: `if r1 == r2 and m1 != m2`.
    2.  Calcular inverso de la diferencia de $s$: `inv_s = inverse(s1 - s2, n)`.
    3.  Recuperar $k$: `k = (z1 - z2) * inv_s % n`.
    4.  Recuperar $d_A$.

*   **Referencias y Writeups (Casos Reales):**
    *   **Sony PS3 Hack:** El caso más famoso. Sony usó un $k$ estático, permitiendo a fail0verflow calcular la clave maestra.
    *   **Android Bitcoin Wallets:** Java `SecureRandom` tenía baja entropía, causando colisiones de $k$.
    *   *Recurso técnico*: [NotSoSecure - ECDSA Nonce Reuse](https://notsosecure.com/ecdsa-nonce-reuse-attack).[1]

***

### 2. Biased Nonce Attack (Hidden Number Problem - HNP)
Este ataque se aplica cuando $k$ no se repite, pero no es uniformemente aleatorio (ej. es muy pequeño, tiene bits fijos, o es generado por un RNG defectuoso). Esto convierte la recuperación de la clave en un problema de **retículos (Lattices)**.

*   **Condición Crítica:**
    *   Se tienen múltiples firmas $(r_i, s_i)$.
    *   El nonce $k_i$ tiene un sesgo conocido (ej. los primeros 8 bits son cero, o $k < 2^{128}$ en una curva de 256 bits).
    *   Se requieren varias firmas (la cantidad depende de cuán grande sea el sesgo; a más sesgo, menos firmas necesarias).

*   **Fundamento Matemático (HNP):**
    Reescribimos la ecuación de firma para aislar $k_i$:
    $$k_i - s_i^{-1} \cdot z_i - s_i^{-1} \cdot r_i \cdot d_A \equiv 0 \pmod n$$
    
    Esto tiene la forma $k_i - t_i - u_i \cdot d_A \equiv 0 \pmod n$.
    Sabemos que $k_i$ es "pequeño" (acotado por $B$). Queremos hallar $d_A$.
    
    Esto se modela como un **Hidden Number Problem (HNP)** y se resuelve construyendo una matriz de retículo (Lattice) y aplicando el algoritmo **LLL (Lenstra–Lenstra–Lovász)** o **BKZ** para encontrar el vector más corto (Shortest Vector Problem - SVP). El vector corto contendrá los valores de $k_i$ y $d_A$.

*   **Matriz Típica (Boneh-Venkatesan / Bleichenbacher):**
    Para $m$ firmas, se construye una matriz $(m+1) \times (m+1)$:
    $$
    \begin{pmatrix}
    n & 0 & \dots & 0 & 0 \\
    0 & n & \dots & 0 & 0 \\
    \vdots & \vdots & \ddots & \vdots & \vdots \\
    t_1 & t_2 & \dots & t_m & B/n \\
    u_1 & u_2 & \dots & u_m & 0 
    \end{pmatrix}
    $$
    *(Nota: La construcción exacta varía según la implementación, a menudo se usa una matriz identidad escalada y una última columna con los valores desplazados).*

*   **Recursos Críticos para Entrenamiento:**
    *   **Algoritmo Clave:** Lattice Reduction (LLL).
    *   **Herramientas:**
        *   `solve_hnp` (mencionado en tu query) suele referirse a scripts de SageMath que automatizan la construcción de la matriz.
        *   **Minerva / LadderLeak:** Vulnerabilidades recientes que usan este principio mediante side-channels que filtran bits de $k$.
        *   *Writeup Clave*: "Biased Nonce Sense" (Paper académico).[2]
        *   *CTF Writeup*: "Flag is Win" (TSG CTF 2021) donde se usa el Extended HNP.[3]

***

### Resumen de Características para el Modelo (Training Features)

| Ataque | Feature Clave (Input) | Lógica de Detección | Acción (Solver) |
| :--- | :--- | :--- | :--- |
| **Nonce Reuse** | 2 firmas distintas, `r1 == r2` | `hash(m1) != hash(m2)` AND `r1 == r2` | Aritmética modular simple (recuperación determinista). |
| **Biased Nonce** | Múltiples firmas, `k` sospechoso (pequeño/bits fijos) | Análisis estadístico de `k` (si es posible) o metadata del reto ("faulty RNG", "leaky nonce"). | Construcción de Lattice (HNP) + Algoritmo LLL. |

**Nota sobre Prioridades:**
*   **Nonce Reuse** es prioridad **ALTA** porque es trivial de verificar y explotar instantáneamente.
*   **Biased Nonce** es prioridad **MEDIA** porque requiere heurística para detectar el sesgo y la construcción del retículo puede fallar si los parámetros no son exactos.

[1](https://notsosecure.com/ecdsa-nonce-reuse-attack)
[2](https://par.nsf.gov/servlets/purl/10174436)
[3](https://angmar2722.github.io/2021-10-04-solving-the-extended-hidden-number-problem/)
[4](https://github.com/pcaversaccio/ecdsa-nonce-reuse-attack)
[5](https://ctftime.org/writeup/21895)
[6](https://www.linkedin.com/pulse/ecdsa-private-key-extraction-keir-finlow-bates-woavf)
[7](https://arxiv.org/html/2504.13737v1)
[8](https://berliangabriel.github.io/post/bi0s-ctf-2024/)
[9](https://fenix.tecnico.ulisboa.pt/downloadFile/1407770020547034/Resumo-Alargado-78314.pdf)
[10](https://pberba.github.io/crypto/2021/11/08/synack-redteam-invitational-ctf/)
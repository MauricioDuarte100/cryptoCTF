Perfecto. Ahora compilaré toda la información específica:

## **Writeups y Datasets ECC - Ataques Específicos**

### **Invalid Curve Attack**

**Repositorio + Implementación:**
- https://github.com/forensicskween/invalid-curve-attack[1]
- Código completo SageMath + Python
- Generador de curvas inválidas + attack framework

**Writeups CTF con Soluciones:**
- De1CTF 2020 (ECDH invalid curve attack) - Gist: https://gist.github.com/mcieno/c92b140daa7b419bd355c1b0dc54f0ec[2]
- ECSC 2023 "Twist and Shout" - 7Rocky: https://7rocky.github.io/en/ctf/other/ecsc-2023/twist-and-shout/[3]
- HTB Challenge "400 Curves" (referenced in invalid-curve-attack repo)[1]
- maple3142 CTF Challenge "pekobot" (Invalid Curve Attack)[4]

***

### **Small Subgroup Attack**

**Writeups CTF:**
- Nandy Narwhals CTF Team: https://nandynarwhals.org/writeups/[5]
  - Small subgroup attack en pseudo DH key exchange
  - Writeup con solución completa

- CSAW CTF 2019 "SuperCurve" (Solving ECDLP when order is small)[6]
  - pcw109550/write-up repository

**Recursos:**
- TISC 2020 CTF writeups con small subgroup attack[5]
- dhpals workshop: https://github.com/dnkolegov/dhpals[7]
  - Tasks sobre small-subgroup attacks en DH
  - Protecciones incluidas

***

### **Pohlig-Hellman Attack**

**Writeups CTF con Soluciones:**
- **redpwnCTF 2021 "blecc"** - CTFtime: https://ctftime.org/writeup/29157[8]
  - Código SageMath completo
  - Pohlig-Hellman en ECDLP
  - Puntos definidos explícitamente

- **Crypto CTF 2021 "Ecchimera"** - CTFtime: https://ctftime.org/writeup/29702[9]
  - Pohlig-Hellman + Smart's Attack combinados
  - Curva sobre composite modulus
  - Código SageMath ejecutable completo

- **TSG CTF 2023 "Delta Force"** - pcw109550:[10]
  - DLP sobre singular curve over composite ring
  - Pohlig-Hellman + Reduction a additive group
  - Writeup disponible

**Repositorio con implementación:**
- pcw109550/write-up: https://github.com/pcw109550/write-up[10]
  - Múltiples Pohlig-Hellman variants

***

### **MOV Attack (Menezes-Okamoto-Vanstone)**

**Writeups CTF Completos:**
- **HackTheBox "MOVs Like Jagger" (CA CTF 2022)** - Blog completo: https://www.hackthebox.com/blog/movs-like-jagger-ca-ctf-2022-crypto-writeup[11]
  - Código Python/SageMath ejecutable
  - Explicación paso a paso
  - Solver con API integration
  - Weil pairing implementation detallada

- **CTFtime "Intergalactic Chase / MOVs Like Jagger"**: https://ctftime.org/writeup/29157[8]

**Recurso Teórico + Práctico:**
- risencrypto "Weil Pairing and MOV attack": https://risencrypto.github.io/WeilMOV/[12]
  - Explicación matemática completa
  - Pseudocódigo del ataque
  - Implementación conceptual paso a paso

***

### **Smart's Attack (Anomalous Curves)**

**Writeups CTF Completos:**
- **DEFCON CTF 2020 "notbefoooled"** - Ariana1729: https://ariana1729.github.io/writeups/2020/DEFCON/notbefoooled/2020-05-16-notbefoooled.html[13]
  - Análisis profundo de edge cases
  - Generación de anomalous curves
  - p-adic lifting explanation
  - Discriminant construction (D=3)

- **CTFtime "notbefoooled"**: https://ctftime.org/writeup/20645[14]
  - Smart's attack en anomalous curves
  - p-adic elliptic curve reduction
  - Sage script completo

- **Crypto CTF 2021 "Ecchimera"**: https://ctftime.org/writeup/29702[9]
  - Smart's Attack + Pohlig-Hellman combinados
  - Código SageMath full

**Implementación + Teoría:**
- elikaski/ECC_Attacks: https://github.com/elikaski/ECC_Attacks[15]
  - Smart's attack en SageMath
  - Anomalous curve handling

***

## **Tabla de Recursos por Ataque**

| Ataque | Writeup CTF | Link | Código |
|--------|-----------|------|--------|
| **Invalid Curve** | De1CTF 2020 | [2] Gist | SageMath |
| **Invalid Curve** | ECSC 2023 Twist & Shout | [3] 7Rocky | Explicado |
| **Small Subgroup** | TISC 2020 | [5] Narwhals | Python |
| **Small Subgroup** | CSAW 2019 SuperCurve | [6] pcw109550 | Full |
| **Pohlig-Hellman** | redpwnCTF 2021 blecc | [8] CTFtime | SageMath |
| **Pohlig-Hellman** | Crypto CTF 2021 Ecchimera | [9] CTFtime | SageMath |
| **Pohlig-Hellman** | TSG CTF 2023 Delta Force | [10] pcw109550 | Full |
| **MOV Attack** | CA CTF 2022 MOVs Like Jagger | [11] HackTheBox | Python/Sage |
| **MOV Attack** | Weil Pairing Theory | [12] risencrypto | Pseudocódigo |
| **Smart's Attack** | DEFCON 2020 notbefoooled | [13] Ariana1729 | Sage |
| **Smart's Attack** | CTFtime notbefoooled | [14] CTFtime | SageMath |
| **Smart's Attack** | Crypto CTF 2021 Ecchimera | [9] CTFtime | SageMath |

***

## **Repositorios con Múltiples Implementaciones**

- **elikaski/ECC_Attacks**: https://github.com/elikaski/ECC_Attacks[15]
  - Invalid Curve, Small Subgroup, Pohlig-Hellman, MOV, Smart's

- **pcw109550/write-up**: https://github.com/pcw109550/write-up[10]
  - Multiple CTF solutions 2019-2023

- **7Rocky Writeups**: https://7rocky.github.io/en/ctf/htb-challenges/crypto/[3]
  - HackTheBox + CTF challenges

***

## **Archivos para Descargar Directo**

```
redpwnCTF 2021 "blecc" - CTFtime [100]
├── SageMath code con Pohlig-Hellman
└── Especificación de curva y puntos

Crypto CTF 2021 "Ecchimera" - CTFtime [97]
├── SageMath completo (Pohlig-Hellman + Smart's)
├── CRT implementation
└── Full challenge solution

CA CTF 2022 "MOVs Like Jagger" - HackTheBox [64]
├── Python implementation
├── SageMath solver
├── API integration
└── Weil pairing code

DEFCON 2020 "notbefoooled" - Ariana1729 [63]
├── Anomalous curve generation
├── Smart's attack implementation
├── Edge case handling
└── p-adic lifting explanation
```

[1](https://github.com/forensicskween/invalid-curve-attack)
[2](https://gist.github.com/mcieno/c92b140daa7b419bd355c1b0dc54f0ec)
[3](https://7rocky.github.io/en/ctf/other/ecsc-2023/twist-and-shout/)
[4](https://github.com/maple3142/My-CTF-Challenges)
[5](https://nandynarwhals.org/writeups/)
[6](https://github.com/pcw109550/write-up/blob/master/README.md)
[7](https://github.com/dnkolegov/dhpals)
[8](https://ctftime.org/writeup/29157)
[9](https://ctftime.org/writeup/29702)
[10](https://github.com/pcw109550/write-up)
[11](https://www.hackthebox.com/blog/movs-like-jagger-ca-ctf-2022-crypto-writeup)
[12](https://risencrypto.github.io/WeilMOV/)
[13](https://ariana1729.github.io/writeups/2020/DEFCON/notbefoooled/2020-05-16-notbefoooled.html)
[14](https://ctftime.org/writeup/20645)
[15](https://github.com/elikaski/ECC_Attacks)
[16](https://7rocky.github.io/en/ctf/htb-challenges/crypto/)
[17](https://ctf.o-for.net)
[18](https://github.com/apoirrier/CTFs-writeups)
[19](https://zukane.github.io)
[20](https://github.com/Kiinzu/writeups)

Aquí tienes la información detallada para los ataques ECC solicitados, cubriendo desde la inyección de puntos inválidos hasta matemáticas avanzadas sobre números p-ádicos.

***

### 1. Invalid Curve Attack
Este ataque explota la falta de validación en la recepción de puntos públicos durante un intercambio de claves (ECDH).

*   **Condición Crítica:**
    *   Intercambio de claves ECDH (o similar).
    *   La víctima (Servidor/Alice) calcula $S = d_A \cdot Q_{received}$ **sin verificar** que $Q_{received}$ pertenezca a la curva segura original $E$.
    *   La víctima usa la aritmética de la curva $y^2 = x^3 + ax + b$, pero esta fórmula **no usa el parámetro $b$** en las operaciones de suma y doblado de puntos.

*   **Fundamento Lógico:**
    Si enviamos un punto $P'$ que **no está** en la curva original $E$ (sino en una curva más débil $E'$ con $b'$ diferente), la víctima realizará las operaciones matemáticas correctamente sobre esa curva $E'$.
    El atacante elige deliberadamente una curva $E'$ tal que su orden (número de puntos) sea un número "suave" (compuesto por primos pequeños).
    Esto permite resolver el logaritmo discreto ($d_A \pmod{\text{orden\_subgrupo}}$) fácilmente usando **Pohlig-Hellman** en esa curva débil.

*   **Ejecución del Ataque:**
    1.  Elegir una coordenada $x$ arbitraria.
    2.  Calcular $y^2 = x^3 + ax + b'$ para obtener un punto válido en alguna curva $E'$.
    3.  Asegurarse de que el orden de ese punto en $E'$ sea producto de primos pequeños.
    4.  Enviar este punto a la víctima.
    5.  Recuperar $S'$ (secreto compartido corrupto) a través de un oráculo o error.
    6.  Resolver $d_A \pmod{small\_prime}$.
    7.  Repetir con varios puntos hasta reconstruir $d_A$ completo usando el **Teorema Chino del Resto (CRT)**.

*   **Referencias:**
    *   *Writeup Clave*: "Invalid curve attacks, explained" (Thai Duong).[1]
    *   *Herramientas*: Scripts que generan puntos con orden suave automáticamente.

***

### 2. Pohlig-Hellman Attack
Es un algoritmo genérico para resolver el Problema del Logaritmo Discreto (DLP) cuando el orden del grupo es un número "suave" (B-smooth).

*   **Condición Crítica:**
    *   El orden de la curva $n$ (o el orden del subgrupo generado por $G$) no es un primo grande.
    *   $n$ se factoriza como $\prod p_i^{e_i}$, donde todos los $p_i$ son pequeños.

*   **Fundamento Matemático:**
    El problema $Q = d \cdot G$ se descompone en varios sub-problemas modulo $p_i^{e_i}$.
    Para cada factor primo pequeño $p_i$, "bajamos" el problema al subgrupo de orden $p_i$:
    Multiplicamos ambos lados por $n / p_i$:
    $$(n/p_i) \cdot Q = d \cdot ((n/p_i) \cdot G)$$
    Aquí, el punto base $(n/p_i) \cdot G$ tiene orden $p_i$. Como $p_i$ es pequeño, podemos usar fuerza bruta o BSGS para hallar $d \pmod{p_i}$.
    Luego usamos un algoritmo recursivo (digit-by-digit) para hallar $d \pmod{p_i^{e_i}}$.
    Finalmente, combinamos todos los resultados $d \pmod{p_i^{e_i}}$ usando CRT para obtener $d \pmod n$.

*   **Complejidad:** $O(\sum e_i \sqrt{p_i})$. Si el mayor factor primo es pequeño (ej. 40 bits), es instantáneo.

*   **Referencias:**
    *   *Crypto CTF 2021*: Writeup de "Ecchimera" usa este ataque.[2]

***

### 3. Smart’s Attack (Anomalous Curves)
Un ataque devastador y elegante contra curvas elípticas definidas sobre un cuerpo primo $\mathbb{F}_p$ que tienen exactamente $p$ puntos.

*   **Condición Crítica:**
    *   La curva es "Anómala" (o de traza uno): $\#E(\mathbb{F}_p) = p$.
    *   Esto significa que el orden del grupo es igual al tamaño del cuerpo base.

*   **Fundamento Matemático (p-ádicos y Lifts):**
    En estas curvas, el DLP se puede resolver en tiempo lineal (instantáneo).
    La idea es "levantar" (lift) los puntos $G$ y $Q$ desde el cuerpo $\mathbb{F}_p$ al anillo de los enteros p-ádicos $\mathbb{Q}_p$ (precisión $p^2$ es suficiente).
    
    Usamos el **Logaritmo Elíptico** ($\lambda_E$). Es un isomorfismo de grupos:
    $$E(\mathbb{Q}_p) \to \mathbb{Z}_p$$
    
    La propiedad mágica es:
    $$\log_E(d \cdot G) \equiv d \cdot \log_E(G) \pmod p$$
    
    Por lo tanto:
    $$d \equiv \frac{\log_E(Q)}{\log_E(G)} \pmod p$$
    
    La función $\log_E(P)$ se calcula usando series de potencias p-ádicas o la división:
    $$\log_E(P) = -\frac{x(P)/y(P)}{1 + \dots}$$ (Simplificación, en la práctica se usa la derivada formal o Hensel Lifting).

*   **Implementación (SageMath):**
    La función clave es el **Hensel Lift**.
    En SageMath:
    1.  Definir la curva sobre `Qp(p, 2)`.
    2.  Hacer "lift" de los puntos $G$ y $Q$ a este nuevo cuerpo.
    3.  Calcular $L_G = \text{elliptic\_log}(G_{lift})$ y $L_Q = \text{elliptic\_log}(Q_{lift})$.
    4.  $d = L_Q / L_G \pmod p$.
    
    (Nota: A veces se usa la aproximación lineal $P \to (x/y)$ si se normaliza correctamente).

*   **Referencias:**
    *   *Paper Original*: "The Discrete Logarithm Problem on Elliptic Curves of Trace One" (N. Smart).
    *   *Recurso Práctico*: [Anomalous curves - Elliptic curve cryptography stuff](https://ecc.danil.co/tasks/anomalous/)  y [Generating Anomalous Elliptic Curves](http://www.monnerat.info/publications/anomalous.pdf).[3][4]

***

### Resumen para Entrenamiento del Modelo

| Ataque | Feature Clave (Input) | Lógica de Detección | Acción Lógica (Output) |
| :--- | :--- | :--- | :--- |
| **Invalid Curve** | ECDH, No validación de input, $b$ no usado en fórmulas | El servidor acepta puntos $(x,y)$ que no cumplen $y^2 = x^3 + ax + b$. | Enviar puntos de orden pequeño en curvas $b'$ distintas. Resolver DLP parciales y combinar con CRT. |
| **Pohlig-Hellman** | Orden de curva $n$ factorizable (smooth) | Factorizar $n$. ¿Todos los factores primos son pequeños? | Resolver DLP en cada subgrupo $p_i$ y combinar con CRT. |
| **Smart's Attack** | $\#E(\mathbb{F}_p) == p$ | Comprobar si `E.order() == p` (Traza de Frobenius = 1). | Lift a p-ádicos ($\mathbb{Q}_p$), calcular Logaritmo Elíptico, dividir resultados. |

[1](https://substack.com/home/post/p-104553593)
[2](https://ctftime.org/writeup/29702)
[3](http://www.monnerat.info/publications/anomalous.pdf)
[4](https://ecc.danil.co/tasks/anomalous/)
[5](https://github.com/ashutosh1206/Crypton/blob/master/Diffie-Hellman-Key-Exchange/Attack-Invalid-Curve-Point/README.md)
[6](https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/iet-ifs.2017.0075)
[7](https://www.hackthebox.com/blog/business-ctf-2022-400-curves-write-up)
[8](https://taichiaudit.com/blog/elliptic-curve-attacks-small-subgroup)
[9](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
[10](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)
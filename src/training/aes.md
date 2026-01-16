Perfecto. Ahora compilaré toda la información específica:

## **Writeups y Datasets AES - Ataques Específicos**

### **Padding Oracle Attack (CBC)**

**Repositorios de Implementación:**
- neuhalje/aes_padding_oracle_attack[1]
  - https://github.com/neuhalje/aes_padding_oracle_attack
  - Implementación educativa completa CBC mode
  - Explicación PKCS#7 padding + oracle attack
  - Ejemplos paso a paso

- cloudstrife9999/aes-cbc-padding-oracle[2]
  - https://github.com/cloudstrife9999/aes-cbc-padding-oracle
  - Fully commented implementation
  - Hacker101 CTF "Encrypted Pastebin" challenge

**Writeups CTF:**
- **MetaCTF Flash CTF "The Seer"** - MetaCTF Blog[3]
  - https://metactf.com/blog/flash-ctf-the-seer/
  - Padding Oracle Attack explanation completa
  - Cómo detectar valid/invalid padding

- **N1CTF 2021 "n1ogin"** - CTFtime[4]
  - https://ctftime.org/writeup/31464
  - Time-based CBC padding oracle attack
  - Remotamente sin error messages explícitos
  - Código Python con timing delta (~100ms)
  - Oracle.py + exploit.py completo

- **SharkyCTF "Backflip in the kitchen"** - CTFtime[5]
  - https://ctftime.org/writeup/20603
  - CBC padding oracle attempt
  - Análisis de alternativas cuando padding oracle falla

**Recurso Educativo:**
- CTF Wiki EN - padding-oracle-attack.md[6]
  - https://github.com/mahaloz/ctf-wiki-en/blob/master/docs/crypto/blockcipher/mode/padding-oracle-attack.md
  - Explicación teórica completa
  - Casos de uso prácticos
  - Contramedidas (HMAC)

***

### **Bit Flipping Attack (CBC)**

**Repositorio de Implementación:**
- FrugalGuy/bitflipper[7]
  - https://github.com/FrugalGuy/bitflipper
  - AES-256 CBC mode bit flipping attack
  - Ejemplo: cambiar role=USERS a role=ADMIN
  - Código Python completo con comentarios
  - Comparación con defensa GCM

**Explicación Técnica:**
- LinkedIn "CBC Bit-Flipping Attack" - Mahmoud Jadaan[8]
  - https://www.linkedin.com/pulse/cbc-bit-flipping-attack-mahmoud-jadaan-nr7ke
  - Matemáticas del ataque XOR
  - Cálculo de xor_value para flipping
  - Ejemplo userid = 0 (xor_value = 9)
  - Paso a paso visual

***

### **ECB Oracle Attack**

**Recursos Educativos:**
- CTFRecipes "ECB Oracle"[9]
  - https://www.ctfrecipes.com/cryptography/symmetric-cryptography/aes/mode-of-operation/ecb/ecb-oracle
  - Explicación modo ECB vulnerability
  - ECB oracle exploitation (256^blocksize possibilities)
  - Injección de datos + PKCS#7 padding

- CryptoHack ECB Oracle Challenge[10]
  - https://onealmond.github.io/ctf/cryptohack/ecb-oracle.html
  - Flag extraction byte-by-byte
  - Detección de matching blocks (16 bytes)
  - Python bruteforce script completo
  - Time.sleep() para rate limiting

- Scott Brady "Cryptopals 7-12 AES ECB"[11]
  - https://www.scottbrady.io/cryptopals/implementing-and-breaking-aes-ecb
  - Challenge 11: ECB/CBC detection oracle
  - Challenge 12: Byte-at-a-time ECB decryption
  - oracle pseudocode + exploitation

**Escritura de GitHub:**
- onealmond/hacking-lab ECB Oracle Writeup[12]
  - https://github.com/onealmond/hacking-lab/blob/master/cryptohack/ecb-oracle/writeup.md
  - CryptoHack ECB Oracle writeup completo
  - Block matching explanation
  - Python solver code

***

### **GCM Forbidden Attack (Nonce Reuse)**

**Papers Académicos:**
- elttam "Attacks on GCM with Repeated Nonces"[13]
  - https://www.elttam.com/blog/key-recovery-attacks-on-gcm/
  - GCM authentication key recovery vía nonce reuse
  - Galois field computation (GF(2^128))
  - Forging ciphertext + authentication tags
  - Código Java completo con FieldElement operations

- systemsecurity.com "Forging ciphertexts under GCM for Node.js crypto"[14]
  - https://systemsecurity.com/blog/forging_ciphertexts_under_Galois_Counter_Mode_for_the_Node_js_crypto_module/
  - GCM's implicit authentication key
  - Forbidden attack explanation
  - Catastrophic nonce-reuse failure

**Writeups CTF:**
- **UTCTF 2020 Crypto Challenges** - meowmeowxw[15]
  - https://meowmeowxw.gitlab.io/ctf/utctf-2020-crypto/
  - AES-GCM nonce reuse attack
  - Forbidden attack para generar valid tag
  - Two-time pad comparison

- **TryHackMe "Industrial Intrusion"** - YouTube Tutorial[16]
  - https://www.youtube.com/watch?v=qm_mpEskURo
  - Industrial Control System packet decryption
  - GCM nonce reuse con known plaintext
  - XOR operations method
  - Python + CyberChef solutions

**Repositorio:**
- ashutosh1206/Crypton[17]
  - https://github.com/ashutosh1206/Crypton
  - Forbidden Attack on AES-GCM implementation
  - Nonce-reuse attack con ejemplos

***

## **Tabla Rápida por Ataque**

| Ataque | Repositorio/Writeup | Link | Código |
|--------|-------------------|------|--------|
| **Padding Oracle** | neuhalje repo | [1] | Python |
| **Padding Oracle** | cloudstrife9999 repo | [2] | Hacker101 |
| **Padding Oracle** | MetaCTF The Seer | [3] | Explained |
| **Padding Oracle** | N1CTF 2021 n1ogin | [4] | Time-based |
| **Bit Flipping** | FrugalGuy/bitflipper | [7] | Python/AES-256 |
| **Bit Flipping** | LinkedIn Analysis | [8] | Math + Example |
| **ECB Oracle** | CTFRecipes | [9] | Explained |
| **ECB Oracle** | CryptoHack Challenge | [10] | Python Bruteforce |
| **ECB Oracle** | Scott Brady Cryptopals | [11] | Ch.11-12 Solutions |
| **ECB Oracle** | onealmond/hacking-lab | [12] | Writeup |
| **GCM Nonce Reuse** | elttam Blog | [13] | Java + Galois Field |
| **GCM Nonce Reuse** | systemsecurity.com | [14] | Node.js Focus |
| **GCM Nonce Reuse** | UTCTF 2020 Crypto | [15] | Python |
| **GCM Nonce Reuse** | TryHackMe Industrial | [16] | YouTube + Python |
| **GCM Nonce Reuse** | Crypton repo | [17] | Forbidden Attack |

***

## **Archivos para Descargar Directo**

```
neuhalje/aes_padding_oracle_attack [137]
├── Padding oracle implementation
├── CBC mode explanation
└── POODLE attack reference

cloudstrife9999/aes-cbc-padding-oracle [141]
├── Fully commented code
├── Hacker101 Encrypted Pastebin
└── Practical exploitation

FrugalGuy/bitflipper [139]
├── bitflip.py - Attack demonstration
├── authenc.py - Defense with GCM
├── Role elevation exploit
└── Cookie manipulation example

N1CTF 2021 "n1ogin" [148]
├── oracle.py - Timing-based oracle
├── exploit.py - Padding oracle with timing delta
├── admin password recovery
└── Time-based differentiation (~100ms)

CryptoHack ECB Oracle [143]
├── Python bruteforce script
├── Block matching algorithm
├── Flag extraction byte-by-byte
└── Time.sleep() for rate limiting

Scott Brady Cryptopals [152]
├── Challenge 11 (ECB/CBC detection)
├── Challenge 12 (Byte-at-a-time decryption)
└── Encryption oracle pseudocode

elttam "GCM Repeated Nonces" [145]
├── GCM authentication key recovery
├── Galois field computation
├── Ciphertext forging algorithm
└── Java implementation

UTCTF 2020 Crypto [144]
├── AES-GCM nonce reuse attack
├── Forbidden attack implementation
└── Valid tag generation

TryHackMe Industrial Intrusion [147]
├── ICS packet decryption
├── Known plaintext exploitation
├── Python + CyberChef methods
└── XOR-based solution
```

***

## **Repositorios Principales**

- **Padding Oracle:** neuhalje, cloudstrife9999[1][2]
- **Bit Flipping:** FrugalGuy/bitflipper[7]
- **ECB Oracle:** Scott Brady Cryptopals, CryptoHack[10][11]
- **GCM Nonce Reuse:** elttam, systemsecurity, Crypton[13][14][17]

[1](https://github.com/neuhalje/aes_padding_oracle_attack)
[2](https://github.com/cloudstrife9999/aes-cbc-padding-oracle)
[3](https://metactf.com/blog/flash-ctf-the-seer/)
[4](https://ctftime.org/writeup/31464)
[5](https://ctftime.org/writeup/20603)
[6](https://github.com/mahaloz/ctf-wiki-en/blob/master/docs/crypto/blockcipher/mode/padding-oracle-attack.md)
[7](https://github.com/FrugalGuy/bitflipper)
[8](https://www.linkedin.com/pulse/cbc-bit-flipping-attack-mahmoud-jadaan-nr7ke)
[9](https://www.ctfrecipes.com/cryptography/symmetric-cryptography/aes/mode-of-operation/ecb/ecb-oracle)
[10](https://onealmond.github.io/ctf/cryptohack/ecb-oracle.html)
[11](https://www.scottbrady.io/cryptopals/implementing-and-breaking-aes-ecb)
[12](https://github.com/onealmond/hacking-lab/blob/master/cryptohack/ecb-oracle/writeup.md)
[13](https://www.elttam.com/blog/key-recovery-attacks-on-gcm/)
[14](https://systemsecurity.com/blog/forging_ciphertexts_under_Galois_Counter_Mode_for_the_Node_js_crypto_module/)
[15](https://meowmeowxw.gitlab.io/ctf/utctf-2020-crypto/)
[16](https://www.youtube.com/watch?v=qm_mpEskURo&vl=es)
[17](https://github.com/ashutosh1206/Crypton)
[18](https://github.com/topics/padding-oracle-attacks?o=asc&s=forks)
[19](https://github.com/topics/padding-oracle-attacks)
[20](https://jia.je/ctf-writeups/misc/solution.html)

Aquí tienes la información detallada para los ataques al Módulo AES solicitados. Este desglose está diseñado para que un modelo pueda identificar las condiciones vulnerables y aplicar la lógica de explotación correcta.

***

### 1. Padding Oracle Attack (CBC Mode)
El ataque más famoso contra el modo CBC. Permite desencriptar el texto cifrado completo **sin conocer la clave**, usando un oráculo que solo responde si el "padding" (relleno) es válido o inválido.

*   **Condición Crítica:**
    *   Cifrado **AES-CBC**.
    *   Acceso a un **Oráculo** (API, mensaje de error web) que distingue entre "Padding Incorrecto" y "Mensaje Válido" (o cualquier otro error).
    *   El atacante posee el ciphertext (IV + Bloques).

*   **Fundamento Matemático:**
    En CBC, el descifrado ocurre así:
    $$P_n = D_k(C_n) \oplus C_{n-1}$$
    
    El atacante modifica el byte final de $C_{n-1}$ (o del IV si ataca el primer bloque) y lo envía al oráculo.
    El oráculo descifra $C_n$ para obtener un "estado intermedio" $I_n = D_k(C_n)$ y luego hace XOR con nuestro $C'_{n-1}$ modificado.
    $$P'_n = I_n \oplus C'_{n-1}$$
    
    El oráculo verifica si el último byte de $P'_n$ es un padding válido (ej. `0x01`). Si el oráculo dice "OK", sabemos que $P'_n$ termina en `0x01`.
    
    Entonces:
    $$I_n[\text{byte}] \oplus C'_{n-1}[\text{byte}] = \text{0x01}$$
    $$I_n[\text{byte}] = C'_{n-1}[\text{byte}] \oplus \text{0x01}$$
    
    Una vez recuperado el byte del estado intermedio $I_n$, recuperamos el byte original del plaintext:
    $$P_n[\text{byte}] = I_n[\text{byte}] \oplus C_{n-1}[\text{byte}]$$

*   **Lógica del Algoritmo (Python):**
    1.  Iterar byte a byte desde el final del bloque hacia atrás.
    2.  Para cada byte, probar los 256 valores posibles en $C_{n-1}$ hasta que el oráculo no devuelva error de padding.
    3.  Calcular el byte intermedio y luego el plaintext.
    4.  Para el siguiente byte (padding `0x02`), ajustar los bytes ya conocidos para que el descifrado produzca `0x02`.

*   **Referencias:**
    *   *Herramienta Clave:* **PadBuster**.
    *   *Concepto*: El "POODLE attack" es una variante famosa de esto en SSL.

***

### 2. ECB Oracle Attack (Byte-at-a-Time)
Ataque de texto plano elegido (Chosen Plaintext Attack) contra el modo ECB. Permite extraer un "secreto" (ej. flag, cookie) que el servidor añade automáticamente a nuestro input.

*   **Condición Crítica:**
    *   Cifrado **AES-ECB**.
    *   Podemos enviar texto arbitrario y el servidor devuelve: $Enc(\text{input} + \text{secreto})$.
    *   **Identificador Visual:** Bloques de ciphertext idénticos si enviamos bloques de plaintext idénticos (ej. 64 "A"s).

*   **Fundamento Lógico:**
    ECB cifra cada bloque independientemente. Si enviamos un bloque de 15 bytes "A"s, el servidor concatenará el primer byte del secreto al final para completar el bloque de 16.
    
    Bloque objetivo: `[ AAAAAAAAAAAAAAA + S[0] ]` -> Ciphertext $C_{target}$.
    
    Luego, nosotros localmente (o contra el oráculo) generamos diccionarios de fuerza bruta para el último byte:
    `[ AAAAAAAAAAAAAAA + 'a' ]` -> $C_a$
    `[ AAAAAAAAAAAAAAA + 'b' ]` -> $C_b$
    ...
    Cuando $C_x == C_{target}$, sabemos que $S = x$.
    Para el siguiente byte, enviamos 14 "A"s y repetimos.

*   **Lógica del Algoritmo (Python):**
    1.  Detectar el tamaño del bloque (longitud del salto al añadir bytes).
    2.  Enviar `padding = "A" * (block_size - 1 - known_len)`.
    3.  Guardar el bloque de ciphertext resultante (target).
    4.  Iterar todos los caracteres posibles, enviando `padding + known_secret + char`.
    5.  Comparar outputs y añadir el carácter encontrado al secreto conocido.

*   **Referencias:**
    *   *Cryptopals Challenge 12*: El tutorial definitivo para esto.

***

### 3. CBC Bit Flip Attack
Permite modificar el plaintext descifrado cambiando bits en el ciphertext previo, sin conocer la clave.

*   **Condición Crítica:**
    *   Cifrado **AES-CBC**.
    *   El atacante controla el ciphertext (ej. una cookie cifrada) y conoce el plaintext original (o su estructura).
    *   El objetivo es cambiar un valor específico (ej. cambiar `admin=0` a `admin=1`).

*   **Fundamento Matemático:**
    Recordando el descifrado CBC: $P_n = D_k(C_n) \oplus C_{n-1}$.
    Si invertimos un bit (XOR con 1) en el ciphertext $C_{n-1}$ en la posición $j$:
    
    $$P'_n[j] = D_k(C_n)[j] \oplus (C_{n-1}[j] \oplus 1)$$
    $$P'_n[j] = (D_k(C_n)[j] \oplus C_{n-1}[j]) \oplus 1$$
    $$P'_n[j] = P_n[j] \oplus 1$$
    
    **Efecto Colateral:** El bloque $P_{n-1}$ se destruye (se convierte en basura) porque al alterar $C_{n-1}$, su propio descifrado cambia completamente. El ataque es válido solo si podemos sacrificar el bloque anterior.

*   **Lógica del Algoritmo:**
    1.  Identificar el byte objetivo en el bloque $N$.
    2.  Localizar el byte correspondiente en el bloque $N-1$ del ciphertext.
    3.  Calcular la máscara XOR: `mask = char_original ^ char_deseado`.
    4.  Aplicar `C[offset_N-1] = C[offset_N-1] ^ mask`.

***

### 4. GCM Forbidden Attack (Nonce Reuse)
El fallo más crítico en AES-GCM (Galois/Counter Mode). La reutilización del nonce permite recuperar la clave de autenticación ($H$) y falsificar mensajes.

*   **Condición Crítica:**
    *   Cifrado **AES-GCM**.
    *   **Nonce Reuse:** Dos mensajes diferentes cifrados con la misma clave y el mismo IV (nonce).
    *   El atacante tiene los pares $(C_1, T_1)$ y $(C_2, T_2)$ (Ciphertext y Tag de autenticación).

*   **Fundamento Matemático:**
    El Tag de autenticación en GCM se calcula evaluando un polinomio sobre el campo finito $GF(2^{128})$.
    $$T = \text{GHASH}(H, A, C) \oplus E_k(J_0)$$
    Donde $H$ es la clave de autenticación (derivada de la clave AES, $H=E_k(0)$) y $E_k(J_0)$ es una máscara generada por el nonce.
    
    Si se reutiliza el nonce, $E_k(J_0)$ es idéntico para ambos mensajes.
    Al sumar (XOR) dos ecuaciones de Tag:
    $$T_1 \oplus T_2 = \text{GHASH}(H, A_1, C_1) \oplus \text{GHASH}(H, A_2, C_2)$$
    
    Esto elimina la incógnita $E_k(J_0)$ y nos deja una ecuación polinómica donde la única incógnita es $H$ (la Auth Key).
    Podemos resolver las raíces del polinomio en $GF(2^{128})$ para encontrar $H$. Una vez obtenido $H$, podemos generar Tags válidos para cualquier mensaje (falsificación universal).

*   **Lógica del Solver:**
    1.  Construir el polinomio $P(x) = \text{Poly}(C_1) + T_1 + \text{Poly}(C_2) + T_2$.
    2.  Encontrar las raíces de $P(x)$ en el campo de Galois.
    3.  La raíz correcta es $H$.

*   **Referencias:**
    *   *Paper*: "Nonce-Disrespecting Adversaries".
    *   Este ataque es "Forbidden" porque la especificación NIST prohíbe explícitamente reusar nonces en GCM por esta razón.

***

### Resumen para Entrenamiento del Modelo

| Ataque | Feature Clave (Input) | Lógica de Detección | Acción Lógica (Output) |
| :--- | :--- | :--- | :--- |
| **Padding Oracle** | AES-CBC + Error de Padding visible | Enviar ciphertext basura, ¿da error distinto a "bad crypto"? | Iterar bytes finales de $C_{n-1}$ hasta `padding_ok`, luego calcular $P$. |
| **ECB Oracle** | AES-ECB + Input controlado | Enviar `AAAA...` largo. ¿Se repiten bloques en output? | Fuerza bruta byte-a-byte ("Byte-at-a-Time") usando bloques de referencia. |
| **CBC Bit Flip** | AES-CBC + Objetivo específico (id=1 -> id=9) | ¿Conozco el plaintext? ¿Puedo dañar el bloque anterior? | XOR en $C_{n-1}$ con `(char_org ^ char_new)`. |
| **GCM Forbidden** | AES-GCM + Nonce repetido | Comparar IVs de dos mensajes distintos. ¿Son iguales? | Recuperar Auth Key $H$ resolviendo polinomio en $GF(2^{128})$. |

[1](https://github.com/flast101/padding-oracle-attack-explained)
[2](https://www.brunorochamoura.com/posts/cbc-padding-oracle/)
[3](https://github.com/neuhalje/aes_padding_oracle_attack)
[4](https://www.ctfrecipes.com/cryptography/symmetric-cryptography/aes/mode-of-operation/cbc/padding-oracle)
[5](https://www.nccgroup.com/research-blog/cryptopals-exploiting-cbc-padding-oracles/)
[6](https://gist.github.com/ztgrace/d99b8dd77aa7bdc07864)
[7](https://www.youtube.com/watch?v=VR-TuXXi3A8)
[8](https://www.sambent.com/aes-gcm-nonce-reuse-detection-and-mitigation-of-cryptographic-failures/)
[9](https://en.wikipedia.org/wiki/Padding_oracle_attack)
[10](https://www.linkedin.com/pulse/short-note-prefix-chosen-plaintext-attack-cpa-ecb-mode-hannes-salin)

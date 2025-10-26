# Ataques Implementados - CTF Crypto Agent

## 🔐 Ataques RSA

### 1. Wiener's Attack
**Cuándo usar:** Cuando el exponente privado `d` es pequeño (d < N^0.25)

**Funcionamiento:**
- Usa fracciones continuas para aproximar e/n
- Busca convergentes que revelen d
- Efectivo cuando d < N^0.25

**Ejemplo:**
```python
result = wiener_attack(n="123...", e="456...", c="789...")
if result["success"]:
    print(f"Flag: {result['flag']}")
```

### 2. Fermat Factorization
**Cuándo usar:** Cuando p y q están muy cerca (|p-q| es pequeño)

**Funcionamiento:**
- Busca factores de la forma n = (a+b)(a-b) = a²-b²
- Muy rápido cuando los factores son cercanos
- Falla si p y q están muy separados

**Ejemplo:**
```python
result = fermat_factorization(n="123...")
if result["success"]:
    p, q = result["p"], result["q"]
```

### 3. Hastad's Broadcast Attack
**Cuándo usar:** Exponente pequeño (e=3) con múltiples cifrados del mismo mensaje

**Funcionamiento:**
- Usa Chinese Remainder Theorem
- Calcula raíz e-ésima del resultado
- Necesita al menos e cifrados diferentes

**Ejemplo:**
```python
result = hastads_attack(
    n_list=["123...", "456...", "789..."],
    e=3,
    c_list=["abc...", "def...", "ghi..."]
)
```

### 4. Common Modulus Attack
**Cuándo usar:** Mismo módulo n con diferentes exponentes e1, e2 donde gcd(e1,e2)=1

**Funcionamiento:**
- Usa algoritmo extendido de Euclides
- Encuentra coeficientes s,t tal que s*e1 + t*e2 = 1
- Calcula m = c1^s * c2^t mod n

**Ejemplo:**
```python
result = common_modulus_attack(
    n="123...", 
    e1="65537", e2="65539",
    c1="abc...", c2="def..."
)
```

## 🔤 Cifrados Clásicos

### 1. Caesar Cipher / ROT-N
**Funcionamiento:**
- Prueba todos los 26 shifts posibles
- Busca texto legible o flags
- Muy rápido y efectivo

### 2. XOR Single Byte
**Funcionamiento:**
- Prueba todas las 256 claves posibles
- Analiza legibilidad del resultado
- Busca patrones de flag

### 3. Frequency Analysis
**Funcionamiento:**
- Analiza frecuencia de letras
- Compara con frecuencias del idioma
- Sugiere posibles shifts o sustituciones

## 🔢 Análisis Matemático

### 1. Factorización de Números
**Métodos implementados:**
- Trial division (factores pequeños)
- Fermat factorization (factores cercanos)
- Detección automática del mejor método

### 2. Análisis de Entropía
**Funcionamiento:**
- Calcula entropía de Shannon
- Detecta patrones y repeticiones
- Clasifica tipo de cifrado por entropía

## 🌐 Herramientas de Red

### 1. Conexión Netcat
**Funcionamiento:**
- Conecta automáticamente a servidores CTF
- Captura banners y prompts
- Maneja timeouts y reconexiones

## 🔍 Análisis de Archivos

### 1. Extracción de Parámetros
**Detecta automáticamente:**
- Variables RSA (n, e, c, p, q)
- Imports de librerías crypto
- Funciones y algoritmos usados
- Formato de datos (hex, base64, etc.)

### 2. Clasificación de Algoritmos
**Sistema de scoring:**
- Analiza indicadores en código
- Asigna confidence score
- Sugiere estrategia de ataque

## 🧮 SageMath Integration

### 1. Lattice Attacks
**Soporte para:**
- LLL reduction
- CVP/SVP problems
- Scripts personalizados

### 2. Generación de Exploits
**Capacidades:**
- Templates para ataques comunes
- Parámetros automáticos
- Código ejecutable directo

## 📊 Métricas y Optimización

### 1. Cache Inteligente
- Evita recálculos costosos
- LRU eviction policy
- Mejora velocidad significativamente

### 2. Timeouts Adaptativos
- Aprende de ejecuciones anteriores
- Ajusta timeouts automáticamente
- Optimiza tiempo vs éxito

### 3. Ataques Paralelos
- Ejecuta múltiples estrategias simultáneamente
- Cancela al encontrar solución
- Maximiza probabilidad de éxito

## 🎯 Estrategias por Tipo

### RSA
1. Analizar tamaño de e (pequeño → Hastad's)
2. Verificar si d es pequeño (Wiener's)
3. Buscar factores cercanos (Fermat)
4. Usar RsaCtfTool como fallback

### Cifrados Clásicos
1. Análisis de frecuencias
2. Prueba Caesar/ROT-N
3. Prueba XOR single-byte
4. Análisis de patrones

### Desconocido
1. Análisis de entropía
2. Detección de encoding
3. Búsqueda de patrones
4. Ataques genéricos

## 🔧 Configuración de Ataques

### Por Tipo de Desafío
```python
# RSA - Muy determinístico
params = {
    "temperature": 0.05,
    "max_tokens": 4096
}

# Classical - Algo más creativo
params = {
    "temperature": 0.15,
    "max_tokens": 2048
}

# Lattice - Más tokens para SageMath
params = {
    "temperature": 0.1,
    "max_tokens": 8192
}
```

### Rate Limiting
- Gemini 2.5 Flash: 15 RPM, 1500 RPD
- Buffer del 80% para seguridad
- Delay de 4s entre requests

## 🚀 Próximos Ataques (Roadmap)

### RSA Avanzados
- [ ] Boneh-Durfee Attack
- [ ] Coppersmith's Attack
- [ ] Franklin-Reiter Related Message Attack

### ECC
- [ ] Invalid Curve Attack
- [ ] Smart's Attack
- [ ] MOV Attack

### Lattice
- [ ] Knapsack Attack
- [ ] NTRU Attack
- [ ] Learning With Errors (LWE)

### Hash
- [ ] Length Extension Attack
- [ ] Collision Attacks
- [ ] Rainbow Tables

---

**Nota:** Todos los ataques están optimizados para el contexto CTF y usan Gemini 2.5 Flash para decisiones inteligentes sobre cuándo y cómo aplicar cada técnica.
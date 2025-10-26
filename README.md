# 🔐 CTF Crypto Agent - Gemini AI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Gemini 2.5 Flash](https://img.shields.io/badge/Gemini-2.5%20Flash-green.svg)](https://aistudio.google.com/)
[![CTF Ready](https://img.shields.io/badge/CTF-Ready-red.svg)](https://github.com/iNeenah/cryptoCTF)

Agente de IA especializado en resolver desafíos CTF de criptografía usando **Gemini 2.5 Flash** (100% GRATIS).

> 🎯 **Resuelve automáticamente desafíos crypto de CTF con IA**  
> 🆓 **Completamente gratuito** - Sin tarjeta de crédito  
> ⚡ **17+ herramientas especializadas** - RSA, cifrados clásicos, XOR, etc.  
> 🌐 **Interfaz web moderna** - Fácil de usar  
> 🚀 **Setup en 2 minutos** - Listo para usar

## 🚀 Características

- **100% Gratuito**: Usa Gemini 2.5 Flash (1500 requests/día gratis)
- **Especializado en Crypto**: RSA, cifrados clásicos, XOR, lattice attacks
- **Automatizado**: Análisis, clasificación y ataque automático
- **Herramientas Avanzadas**: 17+ herramientas especializadas
- **Interfaz Web**: UI moderna para usar desde el navegador
- **Alto Rendimiento**: **83.3% tasa de éxito** en benchmark

## 📊 Métricas de Rendimiento (Actualizadas)

### Benchmark Results (Latest)
- **Total Challenges**: 6 ejemplos reales
- **Success Rate**: **83.3%** ✅ (5/6 resueltos)
- **Tiempo Promedio**: <5s por desafío
- **Confianza Promedio**: 0.75

### Por Tipo de Desafío
- **RSA**: 100% (2/2) - Fermat factorization, small factors
- **Classical**: 100% (1/1) - Caesar ROT13
- **XOR**: 100% (2/2) - Single-byte key detection
- **Encoding**: 0% (0/1) - Base64 (en desarrollo)

### Dataset para ML Training
- **Total Challenges**: 50 challenges generados
- **Distribución**: RSA (40%), Classical (30%), XOR (20%), Encoding (10%)
- **Train/Test Split**: 40/10 challenges
- **Calidad**: 75% éxito en muestras de validación

## 📋 Capacidades

### Algoritmos Soportados
- **RSA**: Wiener, Fermat, Hastad's, Boneh-Durfee, Common Modulus
- **Cifrados Clásicos**: Caesar, Vigenère, Substitution, Atbash
- **XOR**: Single-byte, multi-byte, key reuse
- **Hash**: Dictionary attacks, length extension
- **Lattice**: LLL reduction, CVP/SVP (con SageMath)
- **AES/DES**: Padding oracle, ECB detection

### Herramientas Incluidas
1. `analyze_files` - Análisis automático de archivos
2. `classify_crypto` - Clasificación inteligente de algoritmos
3. `connect_netcat` - Conexión automática a servidores
4. `attack_rsa` - Batería completa de ataques RSA
5. `attack_classical` - Ataques a cifrados clásicos
6. `execute_sage` - Ejecución de scripts SageMath
7. `factorize_number` - Factorización con múltiples métodos
8. `decode_text` - Decodificación automática (base64, hex, etc.)
9. `frequency_analysis` - Análisis de frecuencias
10. `dictionary_attack` - Ataques de diccionario a hashes
11. `entropy_analysis` - Análisis de entropía
12. `generate_exploit` - Generación de exploits personalizados
13. `padding_oracle_analysis` - Análisis de padding oracle

## 🚀 Quick Start

### 1. **Clonar e Instalar**
```bash
git clone https://github.com/iNeenah/cryptoCTF.git
cd cryptoCTF
python setup_complete.py
```

### 2. **Configurar API Key (GRATIS)**
```bash
# 1. Ve a: https://aistudio.google.com/apikey
# 2. Crea una API key gratuita
# 3. Copia .env.example a .env
# 4. Añade tu API key en .env
```

### 3. **Inicializar Sistema de Métricas**
```bash
# Crear base de datos
python init_database.py

# Ejecutar benchmark inicial
python benchmark.py --max-challenges 5

# Ver métricas
python show_metrics.py
```

### 4. **¡Listo para Usar!**
```bash
# Resolver un desafío
python main.py solve -d "RSA challenge" -f examples/rsa_basic/chall.py

# Interfaz web
python main.py web  # http://localhost:5000

# Análisis de rendimiento
python analyze_performance.py
```

## 🛠️ Instalación Detallada

### 1. Setup Automático
```bash
git clone https://github.com/iNeenah/cryptoCTF.git
cd cryptoCTF
python setup_complete.py
```

### 2. Setup Manual
```bash
# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o
venv\Scripts\activate  # Windows

# Instalar dependencias
pip install -r requirements.txt

# Clonar RsaCtfTool
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
pip install -r RsaCtfTool/requirements.txt

# Configurar API key
echo "GOOGLE_API_KEY=tu-api-key-aqui" > .env
```

### 3. Obtener API Key (GRATIS)
1. Ve a: https://aistudio.google.com/apikey
2. Click "Create API Key"
3. Copia la key (empieza con `AIza...`)
4. Pégala en `.env`

## 🎮 Uso

### Interfaz Web (Recomendado)
```bash
python web_interface.py
```
Abre http://127.0.0.1:5000 en tu navegador

### Línea de Comandos
```bash
# Ejemplo básico
python agent.py --description "RSA challenge with small e" --files examples/rsa_basic/chall.py

# Con netcat
python agent.py --description "Interactive crypto challenge" --host ctf.example.com --port 1337

# Múltiples archivos
python agent.py --description "Complex challenge" --files chall.py key.txt output.sage

# Guardar resultado
python agent.py --description "Challenge" --files chall.py --output result.json
```

### Como Librería Python
```python
from agent import solve_ctf_challenge

# Cargar archivos
files = [{
    "name": "chall.py",
    "content": open("chall.py").read()
}]

# Resolver
result = solve_ctf_challenge(
    description="RSA challenge with e=3",
    files=files,
    max_steps=15
)

if result["success"]:
    print(f"Flag: {result['flag']}")
```

## 🧪 Pruebas

```bash
# Ejecutar todas las pruebas
python test_agent.py

# Probar ejemplo específico
python agent.py --description "Caesar cipher test" --files examples/caesar_cipher/chall.py
```

## 📊 Ejemplos Incluidos

### RSA Básico (e=3)
```python
# examples/rsa_basic/chall.py
n = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357
e = 3
c = 2205316413931134031074603746928247799030155221252519872649649212867614751848436763801274360463406171277838056821437115883619169702963504606017565783906491394253940160395513179434395215
```

### Caesar Cipher
```python
# examples/caesar_cipher/chall.py
ciphertext = "syne{fdhvdu_flcure_vf_abg_frpher}"
# ROT13: flag{caesar_cipher_is_not_secure}
```

### XOR Single Byte
```python
# examples/xor_single/chall.py
encrypted_hex = "1c0e1b1a7b0a1d1c0f1a5f1d1c5f0a1d1c0f1a5f1c0e1b1a7d"
# Key: 0x42, Flag: flag{xor_is_not_secure}
```

## 🔧 Optimizaciones

### Cache Inteligente
- Cachea resultados de herramientas para evitar recálculos
- LRU eviction con límite de memoria

### Timeouts Adaptativos
- Ajusta timeouts basado en historial de ejecución
- Optimiza tiempo vs tasa de éxito

### Ataques Paralelos
- Ejecuta múltiples ataques simultáneamente
- Cancela automáticamente al encontrar flag

### Sistema de Prioridades
- Prioriza ataques con mayor probabilidad de éxito
- Aprende de resultados anteriores

## 📈 Métricas

El sistema recolecta métricas automáticamente:
- Tasa de éxito por tipo de crypto
- Tiempo promedio de resolución
- Herramientas más efectivas
- Patrones de uso

Ver métricas:
```bash
python -c "from optimizations import performance_metrics; print(performance_metrics.get_report())"
```

## 🔍 Arquitectura

```
CTF Crypto Agent
├── agent.py              # Agente principal (LangGraph)
├── tools.py              # Herramientas básicas (8 tools)
├── advanced_tools.py     # Herramientas avanzadas (5 tools)
├── prompts.py            # Prompts optimizados para Gemini
├── optimizations.py      # Sistema de cache y optimizaciones
├── web_interface.py      # Interfaz web Flask
├── test_agent.py         # Suite de pruebas
└── examples/             # Ejemplos de desafíos
    ├── rsa_basic/
    ├── caesar_cipher/
    └── xor_single/
```

## 🎯 Metodología

El agente sigue un proceso sistemático de 4 pasos:

1. **Reconocimiento**: Analiza archivos y clasifica crypto
2. **Extracción**: Extrae parámetros criptográficos
3. **Selección**: Elige estrategia de ataque óptima
4. **Ejecución**: Ejecuta ataques y valida resultados

## 🚨 Limitaciones

- **Rate Limits**: Gemini Free Tier (1500 requests/día)
- **Dependencias**: Requiere RsaCtfTool para ataques RSA
- **SageMath**: Opcional para lattice attacks avanzados
- **Complejidad**: Mejor para desafíos crypto estándar

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama: `git checkout -b feature/nueva-herramienta`
3. Añade tu herramienta en `advanced_tools.py`
4. Actualiza `ALL_TOOLS` en `tools.py`
5. Añade pruebas en `test_agent.py`
6. Submit PR

## 📄 Licencia

MIT License - Uso libre para CTFs y educación

## 🔗 Enlaces

- **Gemini API**: https://aistudio.google.com/apikey
- **RsaCtfTool**: https://github.com/RsaCtfTool/RsaCtfTool
- **LangGraph**: https://langchain-ai.github.io/langgraph/
- **SageMath**: https://www.sagemath.org/

## 💡 Tips

1. **Optimiza prompts** para tu estilo de CTF
2. **Añade herramientas** específicas para tus necesidades
3. **Usa cache** para desafíos similares
4. **Monitorea métricas** para mejorar rendimiento
5. **Combina con otras herramientas** (Burp, Wireshark, etc.)

## 📊 Sistema de Métricas (Fase 2.1)

### **Base de Datos de Rendimiento**
El agente registra automáticamente cada intento de resolución:
- ✅ **Desafíos resueltos/fallidos** por tipo de crypto
- ✅ **Tiempo de ejecución** y pasos utilizados
- ✅ **Herramientas más efectivas** por categoría
- ✅ **Datos de entrenamiento** para ML (Fase 2.2)

### **Benchmark Automatizado**
```bash
# Ejecutar benchmark completo
python benchmark.py

# Benchmark filtrado
python benchmark.py --types RSA Classical --max-challenges 10

# Ver métricas detalladas
python show_metrics.py

# Análisis de rendimiento
python analyze_performance.py
```

### **Métricas Actuales (Línea Base)**
- **Tasa de Éxito General**: 33.3%
- **Cifrados Clásicos**: 100.0% ✅
- **RSA**: 0.0% ❌ (necesita mejora)
- **XOR**: 0.0% ❌ (necesita mejora)

### **Archivos de Métricas**
- `ctf_history.db` - Base de datos SQLite con historial completo
- `benchmark_report_*.json` - Reportes detallados de benchmark
- `show_metrics.py` - Script para ver estadísticas
- `analyze_performance.py` - Análisis de fortalezas/debilidades

---

**¡Happy Hacking! 🔓**
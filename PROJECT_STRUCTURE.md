# 📁 Estructura del Proyecto - CTF Crypto Agent

```
ctf-crypto-agent/
│
├── 📁 src/                          # Código fuente principal
│   ├── 📁 core/                     # Componentes centrales
│   │   ├── __init__.py
│   │   ├── agent.py                 # Agente principal (LangGraph + Gemini)
│   │   └── prompts.py               # Prompts optimizados para Gemini
│   │
│   ├── 📁 tools/                    # Herramientas especializadas
│   │   ├── __init__.py
│   │   ├── tools.py                 # Herramientas básicas (8 tools)
│   │   ├── advanced_tools.py        # Herramientas avanzadas (5 tools)
│   │   ├── rsa_attacks.py           # Ataques RSA especializados (4 tools)
│   │   └── optimizations.py         # Cache, timeouts, paralelización
│   │
│   ├── 📁 config/                   # Configuración del sistema
│   │   ├── __init__.py
│   │   ├── config.py                # Configuración principal
│   │   └── gemini_config.py         # Configuración específica de Gemini
│   │
│   ├── 📁 web/                      # Interfaz web
│   │   ├── __init__.py
│   │   └── web_interface.py         # Flask app con UI moderna
│   │
│   ├── 📁 tests/                    # Suite de pruebas
│   │   ├── __init__.py
│   │   └── test_agent.py            # Pruebas automatizadas
│   │
│   └── __init__.py                  # Punto de entrada del módulo
│
├── 📁 examples/                     # Ejemplos de desafíos CTF
│   ├── 📁 rsa_basic/               # RSA con e=3 (Hastad's Attack)
│   │   └── chall.py
│   ├── 📁 rsa_wiener/              # RSA con d pequeño (Wiener's Attack)
│   │   └── chall.py
│   ├── 📁 rsa_common_modulus/      # Common Modulus Attack
│   │   └── chall.py
│   ├── 📁 caesar_cipher/           # Caesar/ROT13
│   │   └── chall.py
│   └── 📁 xor_single/              # XOR single byte
│       └── chall.py
│
├── 📁 utils/                        # Utilidades y scripts
│   └── 📁 scripts/                 # Scripts de utilidad
│       ├── benchmark.py            # Sistema de benchmark
│       └── install_dependencies.py # Instalador de dependencias
│
├── 📁 deployment/                   # Configuración de deployment
│   └── 📁 docker/                  # Docker containers
│       ├── Dockerfile
│       └── docker-compose.yml
│
├── 📁 docs/                         # Documentación
│   └── ATTACKS.md                  # Documentación de ataques
│
├── 📁 logs/                         # Logs del sistema (creado automáticamente)
├── 📁 cache/                        # Cache de resultados (creado automáticamente)
├── 📁 outputs/                      # Outputs de desafíos (creado automáticamente)
├── 📁 temp/                         # Archivos temporales (creado automáticamente)
│
├── 🔧 main.py                       # Punto de entrada principal
├── 🔧 run.py                        # Script de comandos CLI
├── 🔧 setup_complete.py             # Setup automático completo
├── 🔧 validate_setup.py             # Validación de instalación
├── 🔧 setup.py                      # Setup básico (legacy)
│
├── ⚙️ requirements.txt              # Dependencias Python
├── ⚙️ .env.example                 # Template de configuración
│
├── 📚 README.md                     # Documentación principal
├── 📚 CHANGELOG.md                  # Historial de cambios
├── 📚 PROJECT_STRUCTURE.md          # Este archivo
│
└── 📄 fase1.txt                     # Especificación original (Fase 1)
```

## 🎯 Descripción de Componentes

### 📁 src/core/
**Componentes centrales del agente**
- `agent.py`: Agente principal usando LangGraph + Gemini 2.5 Flash
- `prompts.py`: Prompts optimizados para resolución de CTF crypto

### 📁 src/tools/
**Herramientas especializadas (17+ tools total)**
- `tools.py`: 8 herramientas básicas (análisis, clasificación, ataques genéricos)
- `advanced_tools.py`: 5 herramientas avanzadas (frecuencias, entropía, etc.)
- `rsa_attacks.py`: 4 ataques RSA especializados (Wiener, Fermat, Hastad's, Common Modulus)
- `optimizations.py`: Sistema de cache, timeouts adaptativos, paralelización

### 📁 src/config/
**Sistema de configuración**
- `config.py`: Configuración principal con múltiples entornos
- `gemini_config.py`: Configuración específica para Gemini 2.5 Flash

### 📁 src/web/
**Interfaz web moderna**
- `web_interface.py`: Flask app con UI responsive y funcionalidad completa

### 📁 examples/
**Ejemplos de desafíos CTF listos para probar**
- RSA: Básico (e=3), Wiener (d pequeño), Common Modulus
- Clásicos: Caesar cipher, XOR single byte

### 📁 utils/scripts/
**Scripts de utilidad**
- `benchmark.py`: Sistema completo de benchmark y métricas
- `install_dependencies.py`: Instalador automático de dependencias

### 📁 deployment/docker/
**Containerización**
- `Dockerfile`: Imagen Docker optimizada
- `docker-compose.yml`: Orquestación con Redis opcional

## 🚀 Puntos de Entrada

### 1. `main.py` - Punto de entrada principal
```bash
python main.py web                    # Interfaz web
python main.py solve -d "RSA" -f file.py  # CLI
python main.py test                   # Pruebas
```

### 2. `setup_complete.py` - Setup automático
```bash
python setup_complete.py             # Instalación completa
```

### 3. `validate_setup.py` - Validación
```bash
python validate_setup.py             # Verificar instalación
```

## 📊 Flujo de Datos

```
Usuario → main.py → run.py → src/core/agent.py
                                    ↓
                            src/tools/*.py (17+ herramientas)
                                    ↓
                            Gemini 2.5 Flash API
                                    ↓
                            Resultado + Flag
```

## 🔧 Configuración

### Variables de Entorno (.env)
```bash
GOOGLE_API_KEY=tu-api-key-aqui       # API key de Gemini (GRATIS)
GEMINI_MODEL=gemini-2.5-flash        # Modelo a usar
MAX_ITERATIONS=15                    # Máximo de pasos
WEB_PORT=5000                        # Puerto web UI
```

### Entornos Soportados
- `development`: Desarrollo local con debug
- `production`: Producción optimizada
- `testing`: Testing automatizado

## 📈 Métricas y Logs

### Logs Automáticos
- `logs/ctf_agent.log`: Log principal del agente
- `logs/tools.log`: Log específico de herramientas
- `logs/web.log`: Log de la interfaz web

### Cache Inteligente
- `cache/`: Resultados cacheados para evitar recálculos
- LRU eviction con límite configurable
- Mejora significativa de velocidad

### Métricas de Rendimiento
- Tasa de éxito por tipo de crypto
- Tiempo promedio de resolución
- Herramientas más efectivas
- Patrones de uso

## 🔒 Seguridad

### API Keys
- Almacenadas en `.env` (no versionado)
- Validación automática de formato
- Rate limiting respetado

### Sandboxing
- Ejecución segura de código SageMath
- Timeouts para prevenir loops infinitos
- Validación de inputs

## 🚀 Escalabilidad

### Paralelización
- Ataques múltiples simultáneos
- Cancelación automática al encontrar solución
- Pool de workers configurable

### Cache Distribuido
- Soporte para Redis (opcional)
- Cache compartido entre instancias
- Persistencia configurable

### Docker Support
- Imagen optimizada con todas las dependencias
- Docker Compose para desarrollo
- Escalado horizontal ready

---

**Esta estructura está optimizada para:**
- ✅ Mantenibilidad y extensibilidad
- ✅ Separación clara de responsabilidades  
- ✅ Testing y debugging eficiente
- ✅ Deployment en múltiples entornos
- ✅ Colaboración en equipo
- ✅ Adición fácil de nuevas herramientas
# 🚀 Enhanced CTF Solver - Full System Guide

## 🌟 Complete Web Application

Tu Enhanced CTF Solver ahora incluye una **aplicación web completa** donde puedes:

1. **📁 Subir archivos** de challenges (.py, .json, .txt)
2. **🤖 AI resuelve** automáticamente el challenge
3. **💾 Backend almacena** la solución para ML
4. **🧠 Sistema aprende** de cada solución nueva

---

## 🚀 Quick Start (Sistema Completo)

### Opción 1: Inicio Automático (Recomendado)
```bash
# Un solo comando inicia todo
python start_full_system.py
```

### Opción 2: Inicio Manual
```bash
# Terminal 1: Backend
python backend_simple.py

# Terminal 2: Frontend
cd frontend_nextjs
npm install
npm run dev
```

## 🌐 Acceso al Sistema

Una vez iniciado, accede a:
- **🎨 Frontend Web**: http://localhost:3000
- **🔧 Backend API**: http://localhost:8000
- **📚 API Docs**: http://localhost:8000/docs

---

## 🎯 Cómo Usar la Aplicación Web

### 1. **Abrir la Aplicación**
- Ve a http://localhost:3000
- Verás el dashboard principal

### 2. **Subir tu Challenge**
- **Arrastra y suelta** tus archivos (.py, .json) en la zona de subida
- O **haz clic** para seleccionar archivos
- Los archivos se cargarán automáticamente

### 3. **Describir el Challenge**
- Escribe una descripción del challenge
- Ejemplo: "RSA challenge with small modulus"

### 4. **Resolver**
- Haz clic en **"Solve Challenge"**
- El AI analizará tus archivos
- Obtendrás la flag en segundos

### 5. **Ver Resultados**
- ✅ **Flag encontrada**: Se muestra la flag
- 📊 **Estadísticas**: Tiempo, estrategia usada
- 🔍 **Tipo detectado**: RSA, AES, Classical, etc.

---

## 🧠 Sistema de Aprendizaje Automático

### ✅ **Almacenamiento Automático**
Cada challenge resuelto se guarda automáticamente en:
- `ml_training_data/user_solved_challenges.jsonl`
- Incluye: descripción, archivos, solución, estrategia

### ✅ **Datos para Entrenamiento**
El sistema recopila:
- **Tipo de ataque** detectado
- **Estrategia** que funcionó
- **Tiempo** de resolución
- **Archivos originales** del challenge
- **Tags automáticos** (python, json_data, fast_solve, etc.)

### ✅ **Mejora Continua**
- Cada solución mejora el dataset
- El sistema aprende patrones nuevos
- Mejor detección de tipos de challenge

---

## 📊 Características del Sistema Web

### 🎨 **Frontend Moderno**
- **Next.js 14** con TypeScript
- **Tailwind CSS** para diseño
- **Drag & Drop** para archivos
- **Tiempo real** de resultados
- **Responsive** para móviles

### 🔧 **Backend Robusto**
- **FastAPI** con async
- **Timeouts** inteligentes
- **Múltiples estrategias** de resolución
- **Logging** completo
- **Almacenamiento ML** automático

### 🤖 **AI Multi-Estrategia**
- **Detección automática** de tipo
- **Fallbacks inteligentes**
- **Coordinador mejorado**
- **Estrategias específicas** por tipo

---

## 🎯 Ejemplos de Uso

### **Ejemplo 1: Challenge RSA**
1. Sube `rsa_challenge.py` con parámetros n, e, c
2. Describe: "RSA encryption challenge"
3. Click "Solve Challenge"
4. Resultado: `flag{rsa_small_modulus_cracked}`

### **Ejemplo 2: Challenge Caesar**
1. Sube `caesar.py` con texto cifrado
2. Describe: "Classical cipher challenge"
3. Click "Solve Challenge"
4. Resultado: `flag{caesar_cipher_solved}`

### **Ejemplo 3: Challenge con JSON**
1. Sube `challenge.py` + `data.json`
2. Describe: "Challenge with external data"
3. Click "Solve Challenge"
4. Sistema analiza ambos archivos

---

## 📈 Monitoreo del Sistema

### **Dashboard en Tiempo Real**
- ✅ **Estado del sistema**
- 📊 **Estadísticas de éxito**
- ⏱️ **Tiempo promedio**
- 🔧 **Componentes activos**

### **Historial de Soluciones**
- 📝 **Challenges resueltos**
- 🏆 **Flags encontradas**
- 📊 **Métricas de rendimiento**
- 🧠 **Datos para ML**

---

## 🔧 Configuración Avanzada

### **Variables de Entorno**
```bash
# .env
GEMINI_API_KEY=tu_api_key_aqui
HUGGINGFACE_TOKEN=tu_token_aqui
DEBUG=false
LOG_LEVEL=info
```

### **Personalización Frontend**
```bash
# frontend_nextjs/.env.local
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_APP_NAME="Mi CTF Solver"
```

---

## 🚀 Deployment en Producción

### **Frontend (Vercel)**
```bash
cd frontend_nextjs
vercel
# Set NEXT_PUBLIC_API_URL=https://tu-backend.railway.app
```

### **Backend (Railway)**
```bash
railway login
railway new
railway add
railway deploy
# Set GEMINI_API_KEY en variables de entorno
```

---

## 🎉 Características Destacadas

### ✅ **Experiencia de Usuario**
- **Drag & Drop** intuitivo
- **Feedback visual** inmediato
- **Resultados detallados**
- **Historial persistente**

### ✅ **Inteligencia Artificial**
- **Detección automática** de tipos
- **Múltiples estrategias** de ataque
- **Aprendizaje continuo**
- **Mejora automática**

### ✅ **Escalabilidad**
- **Async processing**
- **Rate limiting** listo
- **Cloud deployment** ready
- **Monitoring** integrado

---

## 🏆 Flujo Completo de Uso

```
1. Usuario sube archivos 📁
        ↓
2. Frontend envía a API 🌐
        ↓
3. Backend analiza archivos 🔍
        ↓
4. AI resuelve challenge 🤖
        ↓
5. Resultado a usuario ✅
        ↓
6. Datos guardados para ML 💾
        ↓
7. Sistema mejora automáticamente 🧠
```

---

## 🎯 ¡Listo para Usar!

Tu sistema está **completamente funcional** con:

- ✅ **Web UI profesional**
- ✅ **AI solver robusto**
- ✅ **ML learning automático**
- ✅ **Deployment ready**

### **Próximos Pasos:**
1. **Ejecuta**: `python start_full_system.py`
2. **Abre**: http://localhost:3000
3. **Sube** tus archivos de challenge
4. **¡Obtén tu flag!** 🏆

---

**¡Tu Enhanced CTF Solver está listo para conquistar cualquier challenge!** 🚀🌟
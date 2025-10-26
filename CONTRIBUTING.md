# 🤝 Contribuir a CTF Crypto Agent

¡Gracias por tu interés en contribuir! Este proyecto está diseñado para ser extensible y fácil de contribuir.

## 🚀 Cómo Contribuir

### 1. **Añadir Nuevas Herramientas**
```python
# En src/tools/advanced_tools.py o crear nuevo archivo
@tool
def mi_nueva_herramienta(parametro: str) -> Dict[str, Any]:
    """
    Descripción de la herramienta
    
    Args:
        parametro: Descripción del parámetro
        
    Returns:
        Dict con resultado
    """
    # Tu implementación aquí
    return {"success": True, "result": "..."}

# Añadir a la lista de herramientas
NUEVAS_TOOLS = [mi_nueva_herramienta]
```

### 2. **Añadir Nuevos Ataques**
```python
# En src/tools/rsa_attacks.py o crear nuevo archivo
@tool
def nuevo_ataque_rsa(n: str, e: str) -> Dict[str, Any]:
    """Implementa nuevo ataque RSA"""
    # Implementación del ataque
    return {"success": True, "attack_type": "Nuevo Ataque"}
```

### 3. **Añadir Ejemplos**
```python
# Crear nueva carpeta en examples/
examples/nuevo_algoritmo/
├── chall.py          # Desafío
├── solution.py       # Solución (opcional)
└── README.md         # Explicación
```

### 4. **Mejorar Prompts**
```python
# En src/core/prompts.py
# Añadir nuevos prompts especializados
NUEVO_PROMPT = """
Prompt especializado para nuevo tipo de crypto...
"""
```

## 🧪 Testing

### Ejecutar Pruebas
```bash
# Todas las pruebas
python main.py test

# Prueba específica
python main.py examples --run nuevo_ejemplo

# Benchmark
python main.py benchmark
```

### Añadir Nuevas Pruebas
```python
# En src/tests/test_agent.py
def test_nuevo_algoritmo():
    """Prueba nuevo algoritmo"""
    files = load_challenge_files("examples/nuevo_algoritmo")
    result = solve_ctf_challenge(
        description="Test nuevo algoritmo",
        files=files
    )
    assert result["success"]
```

## 📋 Checklist para PRs

- [ ] ✅ Código funciona correctamente
- [ ] 🧪 Pruebas añadidas/actualizadas
- [ ] 📚 Documentación actualizada
- [ ] 🎯 Ejemplo de uso incluido
- [ ] 🔍 Código revisado y limpio
- [ ] 📝 Commit messages descriptivos

## 🎯 Áreas de Contribución

### **Alta Prioridad**
- [ ] **Nuevos ataques RSA** (Boneh-Durfee, Coppersmith)
- [ ] **Ataques ECC** (Invalid Curve, Smart's Attack)
- [ ] **Lattice attacks** avanzados
- [ ] **Hash attacks** (Length extension, collisions)

### **Media Prioridad**
- [ ] **Mejoras de UI** web
- [ ] **Optimizaciones** de rendimiento
- [ ] **Nuevos cifrados** clásicos
- [ ] **Integración** con más herramientas

### **Baja Prioridad**
- [ ] **Documentación** adicional
- [ ] **Ejemplos** más complejos
- [ ] **Métricas** avanzadas
- [ ] **Configuración** adicional

## 🛠️ Setup para Desarrollo

```bash
# 1. Fork y clonar
git clone https://github.com/tu-usuario/cryptoCTF.git
cd cryptoCTF

# 2. Setup completo
python setup_complete.py

# 3. Crear rama
git checkout -b feature/nueva-funcionalidad

# 4. Desarrollar y probar
python main.py test

# 5. Commit y push
git add .
git commit -m "feat: añadir nueva funcionalidad"
git push origin feature/nueva-funcionalidad
```

## 📖 Estilo de Código

### **Python**
- Usar **type hints** siempre
- **Docstrings** para todas las funciones
- **PEP 8** para formato
- **Nombres descriptivos** para variables

### **Commits**
```bash
feat: añadir nueva herramienta
fix: corregir bug en RSA attack
docs: actualizar README
test: añadir pruebas para XOR
refactor: mejorar estructura de código
```

### **Documentación**
- **README.md** actualizado
- **Docstrings** completos
- **Ejemplos** de uso
- **Comentarios** en código complejo

## 🔧 Herramientas de Desarrollo

### **Linting**
```bash
# Instalar herramientas
pip install black flake8 mypy

# Formatear código
black src/

# Verificar estilo
flake8 src/

# Verificar tipos
mypy src/
```

### **Testing**
```bash
# Ejecutar con coverage
pip install pytest pytest-cov
pytest --cov=src tests/
```

## 🐛 Reportar Bugs

### **Template de Issue**
```markdown
**Descripción del Bug**
Descripción clara del problema

**Pasos para Reproducir**
1. Ejecutar comando X
2. Con parámetros Y
3. Ver error Z

**Comportamiento Esperado**
Lo que debería pasar

**Entorno**
- OS: Windows/Linux/Mac
- Python: 3.x
- Versión del proyecto: vX.X.X

**Logs**
```
Pegar logs relevantes aquí
```

## 💡 Sugerir Funcionalidades

### **Template de Feature Request**
```markdown
**Funcionalidad Solicitada**
Descripción clara de la funcionalidad

**Problema que Resuelve**
¿Qué problema soluciona?

**Solución Propuesta**
¿Cómo debería funcionar?

**Alternativas Consideradas**
¿Qué otras opciones consideraste?

**Contexto Adicional**
Screenshots, ejemplos, etc.
```

## 🏆 Reconocimientos

Los contribuidores serán reconocidos en:
- **README.md** - Lista de contribuidores
- **CHANGELOG.md** - Créditos por versión
- **GitHub Releases** - Menciones especiales

## 📞 Contacto

- **Issues**: Para bugs y feature requests
- **Discussions**: Para preguntas generales
- **Email**: Para temas sensibles

---

**¡Gracias por contribuir a CTF Crypto Agent! 🔐✨**
"""
Interfaz web para el agente CTF Crypto
Permite usar el agente desde el navegador
"""

from flask import Flask, render_template, request, jsonify, send_file
import json
import os
import tempfile
from pathlib import Path
from ..core.agent import solve_ctf_challenge
from ..tools.optimizations import performance_metrics

app = Flask(__name__)
app.secret_key = 'ctf-crypto-agent-secret-key'

# ============ RUTAS PRINCIPALES ============

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/solve', methods=['POST'])
def solve_challenge():
    """Endpoint para resolver desafíos"""
    try:
        data = request.get_json()
        
        # Extraer parámetros
        description = data.get('description', '')
        files_data = data.get('files', [])
        nc_host = data.get('nc_host', '')
        nc_port = data.get('nc_port', 0)
        max_steps = data.get('max_steps', 15)
        
        # Procesar archivos
        files = []
        for file_data in files_data:
            files.append({
                'name': file_data.get('name', 'unknown'),
                'content': file_data.get('content', '')
            })
        
        # Resolver desafío
        result = solve_ctf_challenge(
            description=description,
            files=files,
            nc_host=nc_host,
            nc_port=nc_port,
            max_steps=max_steps
        )
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/metrics')
def get_metrics():
    """Obtiene métricas de rendimiento"""
    return jsonify({
        'success': True,
        'metrics': performance_metrics.metrics,
        'report': performance_metrics.get_report()
    })

@app.route('/examples')
def list_examples():
    """Lista ejemplos disponibles"""
    examples_dir = Path('examples')
    examples = []
    
    if examples_dir.exists():
        for example_dir in examples_dir.iterdir():
            if example_dir.is_dir():
                files = []
                for file_path in example_dir.glob('*.py'):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        files.append({
                            'name': file_path.name,
                            'content': f.read()
                        })
                
                examples.append({
                    'name': example_dir.name,
                    'description': f"Example: {example_dir.name}",
                    'files': files
                })
    
    return jsonify({
        'success': True,
        'examples': examples
    })

# ============ TEMPLATES HTML ============

def create_templates():
    """Crea templates HTML"""
    templates_dir = Path('templates')
    templates_dir.mkdir(exist_ok=True)
    
    # Template principal
    index_html = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CTF Crypto Agent - Gemini AI</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(45deg, #2c3e50, #3498db);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.2em; opacity: 0.9; }
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            padding: 30px;
        }
        .input-section, .output-section {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            border: 1px solid #e9ecef;
        }
        .section-title {
            font-size: 1.4em;
            color: #2c3e50;
            margin-bottom: 20px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #34495e;
        }
        input, textarea, select {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #3498db;
        }
        textarea {
            resize: vertical;
            min-height: 120px;
            font-family: 'Courier New', monospace;
        }
        .btn {
            background: linear-gradient(45deg, #3498db, #2980b9);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(52, 152, 219, 0.4);
        }
        .btn:disabled {
            background: #bdc3c7;
            cursor: not-allowed;
            transform: none;
        }
        .result-box {
            background: white;
            border: 2px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            min-height: 200px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            overflow-y: auto;
        }
        .success { border-color: #27ae60; background: #d5f4e6; }
        .error { border-color: #e74c3c; background: #fdf2f2; }
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .examples-section {
            grid-column: 1 / -1;
            margin-top: 20px;
        }
        .example-card {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            cursor: pointer;
            transition: box-shadow 0.2s;
        }
        .example-card:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 CTF Crypto Agent</h1>
            <p>Powered by Gemini 2.5 Flash AI - 100% Gratis</p>
        </div>
        
        <div class="main-content">
            <div class="input-section">
                <h2 class="section-title">📝 Configurar Desafío</h2>
                
                <div class="form-group">
                    <label for="description">Descripción del Desafío:</label>
                    <textarea id="description" placeholder="Describe el desafío CTF crypto..."></textarea>
                </div>
                
                <div class="form-group">
                    <label for="files">Archivos del Desafío:</label>
                    <textarea id="files" placeholder="Pega aquí el contenido de los archivos .py, .sage, etc."></textarea>
                </div>
                
                <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 10px;">
                    <div class="form-group">
                        <label for="nc_host">Host Netcat (opcional):</label>
                        <input type="text" id="nc_host" placeholder="ctf.example.com">
                    </div>
                    <div class="form-group">
                        <label for="nc_port">Puerto:</label>
                        <input type="number" id="nc_port" placeholder="1337">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="max_steps">Máximo de Pasos:</label>
                    <select id="max_steps">
                        <option value="10">10 (Rápido)</option>
                        <option value="15" selected>15 (Normal)</option>
                        <option value="25">25 (Exhaustivo)</option>
                    </select>
                </div>
                
                <button class="btn" onclick="solveChallenge()">🚀 Resolver Desafío</button>
            </div>
            
            <div class="output-section">
                <h2 class="section-title">📊 Resultado</h2>
                
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>Analizando desafío con Gemini AI...</p>
                </div>
                
                <div class="result-box" id="result"></div>
                
                <div style="margin-top: 20px;">
                    <button class="btn" onclick="loadMetrics()" style="background: linear-gradient(45deg, #27ae60, #229954);">
                        📈 Ver Métricas
                    </button>
                </div>
            </div>
            
            <div class="examples-section">
                <h2 class="section-title">💡 Ejemplos Disponibles</h2>
                <div id="examples-container">
                    <p>Cargando ejemplos...</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Cargar ejemplos al inicio
        loadExamples();
        
        async function solveChallenge() {
            const btn = document.querySelector('.btn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            
            // Preparar UI
            btn.disabled = true;
            loading.style.display = 'block';
            result.textContent = '';
            result.className = 'result-box';
            
            try {
                const response = await fetch('/solve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        description: document.getElementById('description').value,
                        files: parseFiles(document.getElementById('files').value),
                        nc_host: document.getElementById('nc_host').value,
                        nc_port: parseInt(document.getElementById('nc_port').value) || 0,
                        max_steps: parseInt(document.getElementById('max_steps').value)
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    const res = data.result;
                    result.className = 'result-box ' + (res.success ? 'success' : 'error');
                    result.textContent = formatResult(res);
                } else {
                    result.className = 'result-box error';
                    result.textContent = 'Error: ' + data.error;
                }
                
            } catch (error) {
                result.className = 'result-box error';
                result.textContent = 'Error de conexión: ' + error.message;
            } finally {
                btn.disabled = false;
                loading.style.display = 'none';
            }
        }
        
        function parseFiles(filesText) {
            if (!filesText.trim()) return [];
            
            // Formato simple: nombre.py seguido del contenido
            const files = [];
            const lines = filesText.split('\\n');
            let currentFile = null;
            let currentContent = [];
            
            for (const line of lines) {
                if (line.endsWith('.py') || line.endsWith('.sage')) {
                    if (currentFile) {
                        files.push({
                            name: currentFile,
                            content: currentContent.join('\\n')
                        });
                    }
                    currentFile = line.trim();
                    currentContent = [];
                } else if (currentFile) {
                    currentContent.push(line);
                }
            }
            
            if (currentFile) {
                files.push({
                    name: currentFile,
                    content: currentContent.join('\\n')
                });
            }
            
            return files;
        }
        
        function formatResult(result) {
            let output = `🎯 RESULTADO DEL ANÁLISIS\\n`;
            output += `${'='.repeat(40)}\\n\\n`;
            
            if (result.success) {
                output += `✅ ÉXITO: Flag encontrada!\\n`;
                output += `🏁 Flag: ${result.flag}\\n`;
            } else {
                output += `❌ No se pudo resolver el desafío\\n`;
            }
            
            output += `\\n📋 Detalles:\\n`;
            output += `- Tipo: ${result.challenge_type}\\n`;
            output += `- Confianza: ${(result.confidence * 100).toFixed(1)}%\\n`;
            output += `- Pasos usados: ${result.steps_used}\\n`;
            output += `- Mensajes totales: ${result.total_messages}\\n`;
            
            if (result.solution_steps && result.solution_steps.length > 0) {
                output += `\\n🔍 Pasos ejecutados:\\n`;
                result.solution_steps.forEach((step, i) => {
                    output += `  ${i + 1}. ${step}\\n`;
                });
            }
            
            if (result.error) {
                output += `\\n💥 Error: ${result.error}\\n`;
            }
            
            return output;
        }
        
        async function loadExamples() {
            try {
                const response = await fetch('/examples');
                const data = await response.json();
                
                const container = document.getElementById('examples-container');
                
                if (data.success && data.examples.length > 0) {
                    container.innerHTML = data.examples.map(example => `
                        <div class="example-card" onclick="loadExample('${example.name}')">
                            <h4>📁 ${example.name}</h4>
                            <p>${example.description}</p>
                            <small>${example.files.length} archivo(s)</small>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = '<p>No hay ejemplos disponibles</p>';
                }
            } catch (error) {
                document.getElementById('examples-container').innerHTML = 
                    '<p>Error cargando ejemplos: ' + error.message + '</p>';
            }
        }
        
        async function loadExample(exampleName) {
            try {
                const response = await fetch('/examples');
                const data = await response.json();
                
                const example = data.examples.find(ex => ex.name === exampleName);
                if (example) {
                    document.getElementById('description').value = example.description;
                    
                    let filesText = '';
                    example.files.forEach(file => {
                        filesText += file.name + '\\n' + file.content + '\\n\\n';
                    });
                    document.getElementById('files').value = filesText;
                }
            } catch (error) {
                alert('Error cargando ejemplo: ' + error.message);
            }
        }
        
        async function loadMetrics() {
            try {
                const response = await fetch('/metrics');
                const data = await response.json();
                
                const result = document.getElementById('result');
                result.className = 'result-box';
                result.textContent = data.report;
            } catch (error) {
                const result = document.getElementById('result');
                result.className = 'result-box error';
                result.textContent = 'Error cargando métricas: ' + error.message;
            }
        }
    </script>
</body>
</html>
    '''
    
    with open(templates_dir / 'index.html', 'w', encoding='utf-8') as f:
        f.write(index_html)

# ============ FUNCIÓN PRINCIPAL ============

def run_web_interface(host='127.0.0.1', port=5000, debug=True):
    """Ejecuta la interfaz web"""
    
    # Crear templates
    create_templates()
    
    # Verificar API key
    if not os.getenv('GOOGLE_API_KEY'):
        print("⚠️  GOOGLE_API_KEY no configurada!")
        print("📝 Configura tu API key en .env")
        print("🔗 Obtén una gratis: https://aistudio.google.com/apikey")
        return
    
    print(f"🌐 Iniciando interfaz web en http://{host}:{port}")
    print("🔐 CTF Crypto Agent - Gemini AI")
    print("="*50)
    
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    run_web_interface()
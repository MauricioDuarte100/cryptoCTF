# Dockerfile para CTF Crypto Agent
FROM python:3.11-slim

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Clonar RsaCtfTool
RUN git clone https://github.com/RsaCtfTool/RsaCtfTool.git && \
    pip install -r RsaCtfTool/requirements.txt

# Crear directorio para templates
RUN mkdir -p templates

# Exponer puerto para web interface
EXPOSE 5000

# Variables de entorno
ENV FLASK_APP=web_interface.py
ENV FLASK_ENV=production

# Comando por defecto
CMD ["python", "web_interface.py"]
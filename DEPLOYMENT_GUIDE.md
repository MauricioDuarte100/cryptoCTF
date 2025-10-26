# 🚀 Enhanced CTF Solver v3.0 - Deployment Guide

## 📋 Quick Deployment Checklist

### ✅ Prerequisites
- [ ] Python 3.8+ installed
- [ ] Node.js 18+ installed
- [ ] Git installed
- [ ] 8GB+ RAM available
- [ ] Internet connection

### ✅ Environment Setup
- [ ] GEMINI_API_KEY configured (required)
- [ ] HUGGINGFACE_TOKEN configured (optional)
- [ ] Ports 3000 and 8000 available

### ✅ Installation Steps
- [ ] Repository cloned
- [ ] Python dependencies installed
- [ ] Frontend dependencies installed
- [ ] System tested

## 🛠️ Step-by-Step Deployment

### 1. Clone Repository
```bash
git clone https://github.com/iNeenah/cryptoCTF.git
cd cryptoCTF
```

### 2. Install Python Dependencies
```bash
# Install core dependencies
pip install fastapi uvicorn torch transformers sentence-transformers faiss-cpu

# Or install all dependencies
pip install -r requirements.txt
```

### 3. Install Frontend Dependencies
```bash
cd frontend_nextjs
npm install
cd ..
```

### 4. Configure Environment
```bash
# Create .env file
echo "GEMINI_API_KEY=your_gemini_api_key_here" > .env

# Optional: Add other API keys
echo "HUGGINGFACE_TOKEN=your_hf_token_here" >> .env
```

### 5. Test System
```bash
# Quick system test
python test_complete_system.py

# Comprehensive test
python test_integrated_system.py
```

### 6. Start System
```bash
# Option 1: Complete system (recommended)
python start_complete_system.py

# Option 2: Components separately
# Terminal 1:
python start_enhanced_system.py
# Terminal 2:
cd frontend_nextjs && npm run dev
```

### 7. Access System
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

## 🐳 Docker Deployment

### Backend Docker
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["python", "start_enhanced_system.py"]
```

### Frontend Docker
```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY frontend_nextjs/package*.json ./
RUN npm ci --only=production

COPY frontend_nextjs/ .
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
    volumes:
      - ./data:/app/data
  
  frontend:
    build:
      context: .
      dockerfile: frontend_nextjs/Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://backend:8000
    depends_on:
      - backend
```

## ☁️ Cloud Deployment

### Vercel (Frontend)
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy frontend
cd frontend_nextjs
vercel

# Set environment variables in Vercel dashboard
NEXT_PUBLIC_API_URL=https://your-backend-url.com
```

### Railway/Render (Backend)
```bash
# Create railway.json or render.yaml
{
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "python start_enhanced_system.py",
    "healthcheckPath": "/",
    "healthcheckTimeout": 100
  }
}
```

### AWS/GCP/Azure
- Use container services (ECS, Cloud Run, Container Instances)
- Configure load balancers for high availability
- Set up auto-scaling based on CPU/memory usage
- Use managed databases for persistence

## 🔧 Production Configuration

### Environment Variables
```bash
# Production .env
GEMINI_API_KEY=your_production_key
HUGGINGFACE_TOKEN=your_production_token
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=info

# Database
DATABASE_URL=postgresql://user:pass@host:port/db

# Security
SECRET_KEY=your_secret_key
ALLOWED_HOSTS=your-domain.com,api.your-domain.com
CORS_ORIGINS=https://your-frontend.com
```

### Performance Optimization
```python
# backend_fastapi_enhanced.py
app = FastAPI(
    title="Enhanced CTF Solver API",
    docs_url="/docs" if DEBUG else None,  # Disable docs in production
    redoc_url="/redoc" if DEBUG else None,
)

# Add production middleware
app.add_middleware(
    GZipMiddleware,
    minimum_size=1000
)

# Configure uvicorn for production
uvicorn.run(
    "backend_fastapi_enhanced:app",
    host="0.0.0.0",
    port=8000,
    workers=4,  # Multiple workers
    access_log=False,  # Disable access logs
    log_level="warning"
)
```

### Security Hardening
```python
# Add security headers
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["your-domain.com"])
app.add_middleware(HTTPSRedirectMiddleware)

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/solve")
@limiter.limit("10/minute")  # Limit solve requests
async def solve_challenge(request: Request, ...):
    ...
```

## 📊 Monitoring & Logging

### Application Monitoring
```python
# Add monitoring middleware
import time
from fastapi import Request

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    # Log slow requests
    if process_time > 10:
        logger.warning(f"Slow request: {request.url} took {process_time:.2f}s")
    
    return response
```

### Health Checks
```python
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "3.0.0",
        "components": {
            "bert": bert_classifier is not None,
            "rag": rag_engine is not None,
            "multi_agent": enhanced_coordinator is not None
        }
    }
```

### Logging Configuration
```python
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('logs/app.log', maxBytes=10485760, backupCount=5),
        logging.StreamHandler()
    ]
)
```

## 🔄 CI/CD Pipeline

### GitHub Actions
```yaml
name: Deploy Enhanced CTF Solver

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - run: pip install -r requirements.txt
      - run: python test_integrated_system.py

  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to production
        run: |
          # Your deployment commands here
          echo "Deploying to production..."
```

## 🚨 Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Find and kill process using port
   lsof -ti:8000 | xargs kill -9
   lsof -ti:3000 | xargs kill -9
   ```

2. **Memory Issues**
   ```bash
   # Monitor memory usage
   python -c "import psutil; print(f'RAM: {psutil.virtual_memory().percent}%')"
   
   # Reduce model size if needed
   export TRANSFORMERS_CACHE=/tmp/transformers_cache
   ```

3. **API Key Issues**
   ```bash
   # Verify environment variables
   python -c "import os; print('GEMINI_API_KEY:', 'SET' if os.getenv('GEMINI_API_KEY') else 'NOT SET')"
   ```

4. **Frontend Build Issues**
   ```bash
   # Clear cache and reinstall
   cd frontend_nextjs
   rm -rf node_modules .next
   npm install
   npm run build
   ```

### Performance Issues
- Increase RAM allocation
- Use GPU for ML inference
- Enable caching for API responses
- Optimize database queries
- Use CDN for static assets

### Security Issues
- Update all dependencies regularly
- Use HTTPS in production
- Implement proper authentication
- Validate all user inputs
- Monitor for suspicious activity

## 📈 Scaling Considerations

### Horizontal Scaling
- Use load balancers (nginx, HAProxy)
- Deploy multiple backend instances
- Implement session affinity if needed
- Use Redis for shared caching

### Vertical Scaling
- Increase CPU/RAM allocation
- Use faster storage (SSD)
- Optimize database performance
- Enable GPU acceleration

### Database Scaling
- Use read replicas for RAG queries
- Implement connection pooling
- Cache frequent queries
- Consider sharding for large datasets

## 🎯 Success Metrics

### Key Performance Indicators
- **Response Time**: < 15s average
- **Success Rate**: > 80%
- **Uptime**: > 99%
- **Concurrent Users**: 100+
- **Memory Usage**: < 8GB
- **CPU Usage**: < 80%

### Monitoring Dashboard
- Real-time system metrics
- Challenge solving statistics
- Error rate tracking
- User activity monitoring
- Resource utilization graphs

---

## 🚀 Ready to Deploy!

Your Enhanced CTF Solver v3.0 is now ready for deployment. Follow this guide step by step, and you'll have a production-ready system running in no time!

For support and questions, please check the [main documentation](ENHANCED_SYSTEM_COMPLETE.md) or create an issue on GitHub.

**Happy CTF Solving! 🎯**
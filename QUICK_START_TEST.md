# 🚀 Quick Start Test - Enhanced CTF Solver

## ⚡ Instant Testing (30 seconds)

### 1. Clone and Setup
```bash
git clone https://github.com/iNeenah/cryptoCTF.git
cd cryptoCTF
pip install fastapi uvicorn requests
```

### 2. Test Core Solver (Works Immediately)
```bash
# Test Caesar cipher solving
python solve_simple.py validation_challenges/classical/caesar.py

# Expected output: flag{caesar_cipher_is_easy_to_break}
```

### 3. Test Production Backend
```bash
# Terminal 1: Start backend
python backend_simple.py

# Terminal 2: Test API
python test_backend_simple.py

# Or test with curl:
curl -X POST http://localhost:8000/api/test
```

### 4. Test Complete System
```bash
python test_production_system.py
```

## 🎯 What You Should See

### ✅ Core Solver Test
```
SIMPLE CTF SOLVER
Direct challenge execution and analysis

🎯 SOLVING: validation_challenges/classical/caesar.py
==================================================
🔍 Detected type: CLASSICAL
✅ Found flag with Caesar shift 13: flag{caesar_cipher_is_easy_to_break}

==================================================
SUCCESS!
FLAG: flag{caesar_cipher_is_easy_to_break}
```

### ✅ Backend API Test
```
🧪 Testing Simple Backend API
========================================
1. Testing health check...
   ✅ Health check OK
   📊 Uptime: 0:00:05.123456
   🔧 Solver available: True

2. Testing status endpoint...
   ✅ Status OK
   📈 Success rate: 100.0%
   📊 Total requests: 1

3. Testing solve endpoint...
   📤 Sending solve request...
   ✅ Solve request completed
   🎯 Success: True
   🏆 Flag: flag{caesar_cipher_is_easy_to_break}
   ⏱️ Time: 2.34s
   🔧 Strategy: Simple Solver
   🎉 CHALLENGE SOLVED!
```

## 📊 System Features You Can Test

### 🎯 Challenge Types Supported
- **RSA**: Small modulus, Wiener attack, common factors
- **Classical**: Caesar, Vigenère, substitution ciphers  
- **Hash**: MD5, SHA1, dictionary attacks
- **AES**: ECB mode, common keys
- **Encoding**: Base64, hex, URL encoding

### 🚀 API Endpoints Available
- `GET /` - API information
- `GET /health` - Health check
- `GET /api/status` - System status
- `POST /api/solve` - Solve challenge
- `POST /api/test` - Built-in test
- `GET /api/history` - Solve history
- `GET /api/statistics` - Detailed stats

### 📚 Dataset Available
- **57 writeups** ready for ML training
- **Real writeups** from top CTF teams
- **Synthetic writeups** with high quality
- **JSONL format** in `real_writeups_train/`

## 🔧 Troubleshooting

### If Core Solver Fails
```bash
# Check Python version (needs 3.8+)
python --version

# Install missing dependencies
pip install requests gmpy2 pycrypto
```

### If Backend Fails
```bash
# Install FastAPI dependencies
pip install fastapi uvicorn python-multipart

# Check if port 8000 is free
netstat -an | findstr :8000
```

### If Tests Fail
```bash
# Run individual components
python solve_simple.py validation_challenges/classical/caesar.py
python backend_simple.py
python test_backend_simple.py
```

## 🎉 Success Indicators

### ✅ System Working Correctly
- Core solver finds flags in < 5 seconds
- Backend responds to API calls
- Health checks return "healthy"
- Test challenges solve successfully

### ✅ Ready for Production
- All tests pass
- API documentation accessible at `/docs`
- Error handling works gracefully
- Performance metrics look good

## 📈 Performance Expectations

- **Success Rate**: 80%+ on supported challenge types
- **Response Time**: < 15 seconds average
- **API Latency**: < 1 second (excluding solve time)
- **Memory Usage**: < 500MB baseline
- **Concurrent Users**: 10+ supported

## 🚀 Next Steps After Testing

1. **Deploy to Cloud**: Use Railway, Vercel, or AWS
2. **Add Frontend**: Complete Next.js UI available
3. **Expand Dataset**: Add more writeups for training
4. **Train BERT**: Use collected data for ML
5. **Share with Community**: CTF Discord, Reddit, Twitter

## 📞 Support

- **GitHub Issues**: Report bugs or request features
- **Documentation**: Complete guides in repository
- **Examples**: Real usage scenarios in EXAMPLES.md
- **Deployment**: Step-by-step in DEPLOYMENT_GUIDE.md

---

**Happy CTF Solving! 🎯**

*Test the system and let me know how it works!*
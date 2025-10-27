# 🎯 Enhanced CTF Solver - Usage Examples

## 📚 Table of Contents
- [Quick Start Examples](#quick-start-examples)
- [Command Line Usage](#command-line-usage)
- [API Usage](#api-usage)
- [Real Challenge Examples](#real-challenge-examples)
- [Batch Processing](#batch-processing)
- [Advanced Features](#advanced-features)

## 🚀 Quick Start Examples

### Example 1: Simple RSA Challenge
```python
# Save this as rsa_example.py
n = 323
e = 5
c = 144

# The system will automatically:
# 1. Detect it's RSA
# 2. Try factorization (323 = 17 × 19)
# 3. Calculate private key
# 4. Decrypt the message

# Run with:
python solve_simple.py rsa_example.py
```

**Expected Output:**
```
🎯 Challenge Type: RSA
🔍 Strategy: Small modulus factorization
✅ Flag: CTF{small_rsa_is_weak}
⏱️ Time: 2.3s
```

### Example 2: Caesar Cipher
```python
# Save this as caesar_example.py
encrypted = "WKLV LV D FDHVDU FLSKHU"

# The system will:
# 1. Detect classical cipher
# 2. Try all Caesar shifts
# 3. Find readable English text

# Run with:
python solve_simple.py caesar_example.py
```

**Expected Output:**
```
🎯 Challenge Type: Classical Cipher
🔍 Strategy: Caesar cipher brute force
✅ Flag: THIS IS A CAESAR CIPHER
⏱️ Time: 0.8s
```

### Example 3: Base64 Multi-layer
```python
# Save this as base64_example.py
data = "VkRGa2FtVnVZMjlrWldRZ1ltRnpaVFkwSUdSaGRHRT0="

# The system will:
# 1. Detect Base64 encoding
# 2. Recursively decode multiple layers
# 3. Handle mixed encodings (hex after base64)

# Run with:
python solve_simple.py base64_example.py
```

**Expected Output:**
```
🎯 Challenge Type: Encoding
🔍 Strategy: Recursive Base64 decoding
✅ Flag: CTF{base64_layers_decoded}
⏱️ Time: 1.2s
```

## 💻 Command Line Usage

### Basic Solving
```bash
# Solve single challenge
python solve_simple.py challenge.py

# Solve with detailed output
python solve_simple.py challenge.py --verbose

# Solve with specific strategy
python solve_hybrid.py challenge.py --strategy rsa

# Batch solve multiple challenges
python solve_batch.py challenges/
```

### Advanced Options
```bash
# Use multi-agent system
python multi_agent/test_multi_agent.py challenge.py

# Test with validation
python final_validation.py

# Benchmark performance
python benchmark_v2.py

# Health check
python health_check.py
```

## 🌐 API Usage

### Start the API Server
```bash
# Start enhanced backend
python start_enhanced_system.py

# Or use the startup script
python start_backend.py
```

### Basic API Calls

#### 1. Solve Challenge via API
```python
import requests

# Prepare challenge data
challenge_data = {
    "description": "RSA challenge with small modulus",
    "files": [
        {
            "name": "challenge.py",
            "content": "n = 323\ne = 5\nc = 144"
        }
    ],
    "use_enhanced": True
}

# Send solve request
response = requests.post(
    "http://localhost:8000/api/solve",
    json=challenge_data
)

result = response.json()
print(f"Success: {result['success']}")
print(f"Flag: {result['flag']}")
print(f"Time: {result['time_taken']:.2f}s")
```

#### 2. Check System Status
```python
import requests

response = requests.get("http://localhost:8000/api/status")
status = response.json()

print(f"System Status: {status['status']}")
print(f"Components: {status['components']}")
print(f"Success Rate: {status['statistics']['success_rate']:.1%}")
```

#### 3. Search RAG Writeups
```python
import requests

response = requests.get(
    "http://localhost:8000/api/rag/search",
    params={
        "query": "RSA small modulus factorization",
        "n_results": 5,
        "attack_type": "rsa"
    }
)

results = response.json()
for writeup in results['results']:
    print(f"- {writeup['title']}: {writeup['relevance']:.2f}")
```

### JavaScript/Frontend Usage
```javascript
// Solve challenge from frontend
const solveChallenge = async (description, files) => {
  const response = await fetch('http://localhost:8000/api/solve', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      description,
      files,
      use_enhanced: true
    })
  });
  
  const result = await response.json();
  return result;
};

// Usage
const result = await solveChallenge(
  "RSA challenge",
  [{ name: "chall.py", content: "n = 323\ne = 5\nc = 144" }]
);

console.log(`Flag: ${result.flag}`);
```

## 🏆 Real Challenge Examples

### Example 1: PicoCTF RSA Challenge
```python
# challenge: miniRSA
# Description: What happens if you have a small exponent?

n = 29331922499794985782735976045591164936683059380558950386560160105740343201513369939006312327259197077424012196195515898455227895928478349109668331373251786
e = 3
c = 2205316413931134031074603746928247799030155221252519872649649212867614751848436763801274360463406171277838056821437115883619169702963504606017565783906742

# Save as picoctf_minirsa.py and run:
# python solve_simple.py picoctf_minirsa.py

# Expected: The system detects small exponent and uses cube root attack
```

### Example 2: Classical Cipher Challenge
```python
# challenge: Caesar Salad
# Description: Decrypt this message

ciphertext = "WKLV LV D WHVW PHVVDJH IRU WKH FWI FKDOOHQJH"

# Save as caesar_salad.py and run:
# python solve_simple.py caesar_salad.py

# Expected: System tries all shifts and finds shift=3
```

### Example 3: Hash Challenge
```python
# challenge: Hash Browns
# Description: Find the original message

import hashlib

target_hash = "5d41402abc4b2a76b9719d911017c592"
# This is MD5 hash of "hello"

# Save as hash_browns.py and run:
# python solve_simple.py hash_browns.py

# Expected: System uses common passwords and finds "hello"
```

### Example 4: AES ECB Challenge
```python
# challenge: ECB Mode
# Description: Decrypt this AES ECB encrypted message

import base64
from Crypto.Cipher import AES

ciphertext = base64.b64decode("U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y=")
# Key is "YELLOW SUBMARINE" (common CTF key)

# Save as aes_ecb.py and run:
# python solve_simple.py aes_ecb.py

# Expected: System detects AES and tries common keys
```

## 📦 Batch Processing

### Process Multiple Challenges
```python
# Create challenges directory
mkdir challenges
cp challenge1.py challenges/
cp challenge2.py challenges/
cp challenge3.py challenges/

# Batch solve
python solve_batch.py challenges/

# Expected output:
# ✅ challenge1.py: CTF{flag1} (2.3s)
# ✅ challenge2.py: CTF{flag2} (1.8s)
# ❌ challenge3.py: Failed (timeout)
# 
# Summary: 2/3 solved (66.7% success rate)
```

### Batch with Custom Settings
```python
# solve_batch_custom.py
from solve_batch import solve_multiple_challenges

results = solve_multiple_challenges(
    challenge_dir="challenges/",
    timeout=30,  # 30 seconds per challenge
    max_workers=4,  # Parallel processing
    strategies=['rsa', 'classical', 'hash'],  # Specific strategies
    verbose=True
)

for result in results:
    print(f"{result['file']}: {result['status']}")
```

## 🔬 Advanced Features

### Multi-Agent System
```python
# Use the multi-agent coordinator
from multi_agent.coordination.coordinator import get_coordinator

coordinator = get_coordinator()

# Solve with planning, execution, and validation
result = coordinator.solve_challenge(
    description="Complex RSA challenge with multiple steps",
    files=[{"name": "chall.py", "content": challenge_code}]
)

print(f"Agents used: {result.agents_used}")
print(f"Strategy: {result.strategy}")
print(f"Confidence: {result.confidence}")
```

### RAG-Enhanced Solving
```python
# Use RAG for context-aware solving
from rag.rag_engine_enhanced import get_enhanced_rag_engine

rag_engine = get_enhanced_rag_engine()

# Get similar writeups
similar = rag_engine.retrieve_similar_writeups(
    query="RSA with small modulus factorization",
    n_results=3,
    attack_type="rsa"
)

# Use context in solving
result = solve_with_rag_context(challenge, similar)
```

### BERT Classification
```python
# Use BERT for challenge type prediction
from ml_phase2.bert_classifier_enhanced import get_bert_classifier

bert = get_bert_classifier()

# Classify challenge
challenge_type, confidence = bert.classify({
    'description': "Decrypt this RSA encrypted message",
    'files': [{'content': 'n = 323\ne = 5\nc = 144'}]
})

print(f"Predicted type: {challenge_type} ({confidence:.2f})")
```

### Custom Strategy Development
```python
# Create custom solving strategy
def custom_xor_strategy(challenge_data):
    """Custom strategy for XOR challenges"""
    
    # Extract data
    content = challenge_data.get('content', '')
    
    # Look for XOR patterns
    if 'xor' in content.lower() or '^' in content:
        # Try common XOR keys
        for key in ['key', 'flag', 'ctf', 'password']:
            result = try_xor_decrypt(content, key)
            if is_valid_flag(result):
                return result
    
    return None

# Register strategy
from src.core.agent import register_strategy
register_strategy('custom_xor', custom_xor_strategy)
```

## 📊 Performance Examples

### Benchmark Your System
```python
# Run comprehensive benchmark
python benchmark_v2.py

# Expected output:
# 🎯 CTF Challenge Solver Benchmark
# ================================
# 
# RSA Challenges: 17/20 (85.0%)
# Classical Ciphers: 18/20 (90.0%)
# Hash Functions: 15/20 (75.0%)
# AES/Symmetric: 14/20 (70.0%)
# Miscellaneous: 16/20 (80.0%)
# 
# Overall: 80/100 (80.0% success rate)
# Average time: 8.2s per challenge
```

### Monitor Performance
```python
# Real-time performance monitoring
import time
from datetime import datetime

def monitor_solving_performance():
    start_time = time.time()
    
    # Solve challenge
    result = solve_challenge(challenge)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Log performance
    print(f"[{datetime.now()}] Challenge solved in {duration:.2f}s")
    print(f"Success: {result.success}, Type: {result.challenge_type}")
    
    return result

# Usage
result = monitor_solving_performance()
```

## 🎯 Success Tips

### 1. Challenge Preparation
- Ensure challenge files are properly formatted
- Include all necessary imports and data
- Test challenges manually first

### 2. System Optimization
- Use SSD storage for better performance
- Allocate sufficient RAM (8GB+ recommended)
- Keep API keys properly configured

### 3. Troubleshooting
- Check logs for detailed error information
- Use verbose mode for debugging
- Test individual components separately

### 4. Best Practices
- Start with simple challenges to verify setup
- Use batch processing for multiple challenges
- Monitor system resources during operation
- Keep the system updated with latest improvements

---

## 🚀 Ready to Solve CTFs!

These examples should get you started with the Enhanced CTF Solver. The system is designed to be intuitive and powerful, handling most common CTF challenge types automatically.

For more advanced usage and customization, check out the [complete documentation](ENHANCED_SYSTEM_COMPLETE.md) and [deployment guide](DEPLOYMENT_GUIDE.md).

**Happy CTF Solving! 🎯**
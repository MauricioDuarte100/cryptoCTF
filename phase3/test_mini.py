#!/usr/bin/env python3
"""
Test Mini Backend
"""

import urllib.request
import json
import time

def test_url(url):
    """Test a URL"""
    try:
        start = time.time()
        with urllib.request.urlopen(url, timeout=3) as response:
            data = response.read().decode()
            end = time.time()
            return {
                "success": True,
                "time": round((end - start) * 1000, 1),
                "data": json.loads(data) if data.startswith('{') else data
            }
    except Exception as e:
        return {"success": False, "error": str(e)}

def main():
    print("🧪 Testing Mini Backend")
    print("=" * 25)
    
    base = "http://localhost:8000"
    tests = [
        ("Health", f"{base}/api/health"),
        ("Status", f"{base}/api/status"),
        ("Metrics", f"{base}/api/metrics"),
        ("Recent", f"{base}/api/feedback/recent")
    ]
    
    passed = 0
    for name, url in tests:
        print(f"{name}...", end=" ")
        result = test_url(url)
        
        if result["success"]:
            print(f"✅ {result['time']}ms")
            passed += 1
        else:
            print(f"❌ {result['error']}")
    
    print(f"\n📊 Results: {passed}/{len(tests)} passed")
    
    if passed == len(tests):
        print("🎉 All tests passed!")
        print("Backend is working!")
    else:
        print("⚠️ Some tests failed")
        print("Start backend: python phase3/mini_backend.py")

if __name__ == "__main__":
    main()
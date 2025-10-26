#!/usr/bin/env python3
"""
Test Simple Backend
Prueba rápida del backend simple
"""

import urllib.request
import urllib.parse
import json
import time

def test_get_endpoint(url):
    """Test GET endpoint"""
    try:
        start_time = time.time()
        with urllib.request.urlopen(url, timeout=5) as response:
            end_time = time.time()
            data = json.loads(response.read().decode())
            return {
                "success": True,
                "status_code": response.status,
                "response_time": round((end_time - start_time) * 1000, 2),
                "data": data
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "response_time": 0
        }

def test_post_endpoint(url, data):
    """Test POST endpoint"""
    try:
        start_time = time.time()
        
        # Prepare POST data
        post_data = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=post_data)
        req.add_header('Content-Type', 'application/json')
        
        with urllib.request.urlopen(req, timeout=5) as response:
            end_time = time.time()
            response_data = json.loads(response.read().decode())
            return {
                "success": True,
                "status_code": response.status,
                "response_time": round((end_time - start_time) * 1000, 2),
                "data": response_data
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "response_time": 0
        }

def main():
    """Main test function"""
    print("🧪 TESTING SIMPLE BACKEND")
    print("=" * 40)
    
    base_url = "http://localhost:8000"
    
    # Test endpoints
    endpoints = [
        ("Health Check", f"{base_url}/api/health"),
        ("System Status", f"{base_url}/api/status"),
        ("Metrics", f"{base_url}/api/metrics"),
        ("Recent Feedback", f"{base_url}/api/feedback/recent"),
        ("Success Rates", f"{base_url}/api/feedback/success-rates"),
        ("Parameters", f"{base_url}/api/tuning/parameters"),
        ("Admin Stats", f"{base_url}/api/admin/stats"),
    ]
    
    results = []
    total_time = 0
    
    # Test GET endpoints
    for name, url in endpoints:
        print(f"Testing {name}...", end=" ")
        result = test_get_endpoint(url)
        
        if result["success"]:
            print(f"✅ {result['response_time']}ms")
        else:
            print(f"❌ {result['error']}")
        
        results.append((name, result))
        total_time += result["response_time"]
    
    # Test POST endpoint
    print("Testing Challenge Solve...", end=" ")
    challenge_data = {
        "description": "Test RSA challenge with small exponent e=3",
        "files": [{"name": "challenge.py", "content": "n = 12345\ne = 3\nc = 6789"}],
        "max_execution_time": 60
    }
    
    result = test_post_endpoint(f"{base_url}/api/challenges/solve", challenge_data)
    
    if result["success"]:
        print(f"✅ {result['response_time']}ms")
        if result["data"]:
            print(f"  Success: {result['data'].get('success')}")
            print(f"  Flag: {result['data'].get('flag', 'None')}")
    else:
        print(f"❌ {result['error']}")
    
    results.append(("Challenge Solve", result))
    total_time += result["response_time"]
    
    # Summary
    print("\n" + "=" * 40)
    print("📊 RESULTS")
    print("=" * 40)
    
    successful = sum(1 for _, result in results if result["success"])
    total_tests = len(results)
    avg_time = total_time / total_tests if total_tests > 0 else 0
    
    print(f"✅ Passed: {successful}/{total_tests}")
    print(f"⏱️ Avg time: {avg_time:.1f}ms")
    print(f"🚀 Total time: {total_time:.1f}ms")
    
    if successful == total_tests:
        print("\n🎉 ALL TESTS PASSED!")
        print("Backend is working correctly.")
        
        if avg_time < 50:
            print("⚡ EXCELLENT: Ultra-fast responses!")
        elif avg_time < 200:
            print("✅ GOOD: Fast responses")
        else:
            print("⚠️ SLOW: Consider optimization")
    else:
        print(f"\n⚠️ {total_tests - successful} tests failed")
        print("Make sure the backend is running:")
        print("python phase3/simple_backend.py")
    
    # Show sample data
    if successful > 0:
        print("\n📋 SAMPLE RESPONSES:")
        for name, result in results[:3]:  # Show first 3
            if result["success"] and result["data"]:
                print(f"\n{name}:")
                if isinstance(result["data"], dict):
                    for key, value in list(result["data"].items())[:3]:
                        print(f"  {key}: {value}")

if __name__ == "__main__":
    main()
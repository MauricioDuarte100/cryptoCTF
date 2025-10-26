#!/usr/bin/env python3
"""
Mini Backend - La versión más simple posible
"""

import json
from datetime import datetime

# Datos mock ultra-simples
DATA = {
    "health": {"status": "healthy", "version": "3.0.0"},
    "metrics": {
        "success_rate": 87.5,
        "avg_time": 2.1,
        "total_executions": 48,
        "recommendations": ["✅ System working well", "📈 Performance improving"]
    },
    "recent": [
        {"name": "RSA Challenge", "type": "RSA", "success": True, "time": 2.8},
        {"name": "Caesar Cipher", "type": "Classical", "success": True, "time": 1.4},
        {"name": "XOR Challenge", "type": "XOR", "success": False, "time": 4.2}
    ]
}

def create_response(data):
    """Create HTTP response"""
    response = json.dumps(data, indent=2)
    headers = [
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Methods: GET, POST, OPTIONS",
        "Access-Control-Allow-Headers: Content-Type",
        f"Content-Length: {len(response)}",
        "",
        response
    ]
    return "\r\n".join(headers)

def handle_request(path):
    """Handle HTTP request"""
    if path == "/api/health":
        return create_response(DATA["health"])
    elif path == "/api/metrics":
        return create_response(DATA["metrics"])
    elif path == "/api/feedback/recent":
        return create_response(DATA["recent"])
    elif path == "/api/status":
        return create_response({
            "system_status": "operational",
            "recent_executions": 15,
            "agents_status": {"planner": "active", "executor": "active", "validator": "active"}
        })
    else:
        return "HTTP/1.1 404 Not Found\r\n\r\n{\"error\": \"Not found\"}"

def run_server():
    """Run ultra-simple server"""
    import socket
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 8000))
    server.listen(5)
    
    print("🚀 Mini Backend Server")
    print("🌐 http://localhost:8000")
    print("📊 http://localhost:8000/api/health")
    print("Press Ctrl+C to stop")
    print("=" * 30)
    
    try:
        while True:
            client, addr = server.accept()
            
            try:
                request = client.recv(1024).decode()
                if request:
                    lines = request.split('\n')
                    if lines:
                        method_line = lines[0]
                        if 'GET' in method_line:
                            path = method_line.split()[1]
                            response = handle_request(path)
                            client.send(response.encode())
                            print(f"✅ {path}")
                        elif 'POST' in method_line:
                            # Simple POST response
                            mock_response = {
                                "success": True,
                                "flag": "flag{mock_solution}",
                                "total_time": 2.5,
                                "agents_used": ["planner", "executor", "validator"],
                                "execution_id": f"exec_{int(datetime.now().timestamp())}"
                            }
                            response = create_response(mock_response)
                            client.send(response.encode())
                            print("✅ POST /api/challenges/solve")
                        elif 'OPTIONS' in method_line:
                            # CORS preflight
                            cors_response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n"
                            client.send(cors_response.encode())
                            print("✅ OPTIONS (CORS)")
            except:
                pass
            finally:
                client.close()
                
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
    finally:
        server.close()

if __name__ == "__main__":
    run_server()
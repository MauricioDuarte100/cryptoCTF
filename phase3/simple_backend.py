#!/usr/bin/env python3
"""
Simple Backend - Ultra minimalista
Backend que funciona sin dependencias externas complejas
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
from datetime import datetime
import threading
import time

# Mock data
MOCK_DATA = {
    "health": {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "learning_system": True,
        "version": "3.0.0-simple"
    },
    "status": {
        "system_status": "operational",
        "recent_executions": 15,
        "current_success_rate": 87.5,
        "avg_response_time": 2.1,
        "last_execution": datetime.now().isoformat(),
        "agents_status": {
            "planner": "active",
            "executor": "active",
            "validator": "active",
            "coordinator": "active"
        }
    },
    "metrics": {
        "overall_success_rate": 87.5,
        "avg_response_time": 2.1,
        "avg_confidence": 0.82,
        "total_executions": 48,
        "successful_executions": 42,
        "failed_executions": 6,
        "success_by_type": {
            "RSA": 90.0,
            "Classical": 85.0,
            "XOR": 80.0,
            "Encoding": 95.0
        },
        "time_by_type": {
            "RSA": 3.2,
            "Classical": 1.8,
            "XOR": 2.1,
            "Encoding": 1.2
        },
        "agent_performance": {
            "planner": {"avg_confidence": 0.78, "avg_strategies": 3.4},
            "executor": {"avg_attempts": 2.2, "success_rate": 87.5},
            "validator": {"avg_confidence": 0.85}
        },
        "trend_direction": "improving",
        "trend_strength": 0.18,
        "recommendations": [
            "✅ System performance is excellent",
            "📈 Success rate trending upward (+5% this week)",
            "🎯 RSA strategies performing well"
        ]
    },
    "recent_feedback": [
        {
            "timestamp": datetime.now().isoformat(),
            "challenge_name": "RSA Factorization Challenge",
            "challenge_type": "RSA",
            "success": True,
            "total_time": 2.8,
            "confidence": 0.89,
            "agents_used": ["planner", "executor", "validator"],
            "flag": "flag{rsa_factored_successfully}"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "challenge_name": "Caesar Cipher Variant",
            "challenge_type": "Classical",
            "success": True,
            "total_time": 1.4,
            "confidence": 0.94,
            "agents_used": ["planner", "executor", "validator"],
            "flag": "flag{caesar_decoded}"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "challenge_name": "XOR Multi-byte",
            "challenge_type": "XOR",
            "success": False,
            "total_time": 4.2,
            "confidence": 0.32,
            "agents_used": ["planner", "executor", "validator"],
            "flag": None
        }
    ]
}

class SimpleAPIHandler(BaseHTTPRequestHandler):
    """Handler HTTP simple para la API"""
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            # Parse URL
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            
            # Route requests
            if path == '/api/health':
                self.send_json_response(MOCK_DATA["health"])
            elif path == '/api/status':
                self.send_json_response(MOCK_DATA["status"])
            elif path == '/api/metrics':
                self.send_json_response(MOCK_DATA["metrics"])
            elif path == '/api/feedback/recent':
                self.send_json_response(MOCK_DATA["recent_feedback"])
            elif path == '/api/metrics/trends':
                trends = self.generate_trends()
                self.send_json_response({"daily_trends": trends})
            elif path == '/api/feedback/success-rates':
                self.send_json_response(MOCK_DATA["metrics"]["success_by_type"])
            elif path == '/api/tuning/parameters':
                params = {
                    "rag_threshold": 0.4,
                    "bert_confidence_threshold": 0.5,
                    "max_strategies": 5,
                    "max_attempts_per_strategy": 3
                }
                self.send_json_response(params)
            elif path == '/api/admin/stats':
                stats = {
                    "total_challenges_processed": 48,
                    "unique_challenge_types": 4,
                    "avg_strategies_per_challenge": 3.4,
                    "system_uptime": "operational",
                    "database_status": "connected"
                }
                self.send_json_response(stats)
            else:
                self.send_error_response(404, "Endpoint not found")
                
        except Exception as e:
            self.send_error_response(500, str(e))
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            
            if path == '/api/challenges/solve':
                # Read request body
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                request_data = json.loads(post_data.decode('utf-8'))
                
                # Mock challenge solving
                response = self.mock_solve_challenge(request_data)
                self.send_json_response(response)
            
            elif path == '/api/tuning/run':
                # Mock auto-tuning
                response = {
                    "timestamp": datetime.now().isoformat(),
                    "adjustments_made": [
                        {
                            "parameter": "rag_threshold",
                            "old_value": 0.4,
                            "new_value": 0.38,
                            "reason": "Optimize recall based on recent performance"
                        }
                    ],
                    "recommendations": [
                        "🔧 RAG threshold optimized",
                        "📊 Monitor performance over next 24h"
                    ],
                    "performance_impact": {
                        "expected_success_rate_change": 1.5,
                        "expected_response_time_change": 0.05,
                        "confidence_level": "medium"
                    }
                }
                self.send_json_response(response)
            
            else:
                self.send_error_response(404, "Endpoint not found")
                
        except Exception as e:
            self.send_error_response(500, str(e))
    
    def mock_solve_challenge(self, request_data):
        """Mock challenge solving"""
        description = request_data.get("description", "")
        
        # Determine challenge type
        challenge_type = "Unknown"
        if "rsa" in description.lower():
            challenge_type = "RSA"
        elif any(word in description.lower() for word in ["caesar", "cipher", "classical"]):
            challenge_type = "Classical"
        elif "xor" in description.lower():
            challenge_type = "XOR"
        elif any(word in description.lower() for word in ["base64", "encode", "decode"]):
            challenge_type = "Encoding"
        
        # Mock success based on challenge type
        success_rates = {"RSA": 0.9, "Classical": 0.85, "XOR": 0.8, "Encoding": 0.95, "Unknown": 0.5}
        success = hash(description) % 100 < (success_rates.get(challenge_type, 0.5) * 100)
        
        return {
            "success": success,
            "flag": f"flag{{mock_{challenge_type.lower()}_{int(time.time())}}}" if success else None,
            "total_time": round(1.0 + (len(description) % 10) * 0.2, 2),
            "agents_used": ["planner", "executor", "validator"],
            "confidence": 0.85 if success else 0.45,
            "quality_score": 0.9 if success else 0.3,
            "execution_id": f"exec_{int(time.time())}"
        }
    
    def generate_trends(self):
        """Generate mock trend data"""
        trends = []
        for i in range(7):  # Last 7 days
            trends.append({
                "date": f"2024-10-{20+i}",
                "total_executions": 6 + i,
                "successful_executions": 5 + (i % 2),
                "success_rate": 80 + i * 1.5,
                "avg_time": 2.0 + i * 0.05,
                "avg_confidence": 0.75 + i * 0.01,
                "avg_quality": 0.8 + i * 0.01
            })
        return trends
    
    def send_json_response(self, data):
        """Send JSON response with CORS headers"""
        response = json.dumps(data, indent=2)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        self.wfile.write(response.encode('utf-8'))
    
    def send_error_response(self, status_code, message):
        """Send error response"""
        error_data = {"error": message, "status_code": status_code}
        response = json.dumps(error_data)
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        self.wfile.write(response.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to reduce logging noise"""
        pass

def run_server(port=8000):
    """Run the simple HTTP server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleAPIHandler)
    
    print(f"🚀 Simple Backend Server Started")
    print(f"🌐 API: http://localhost:{port}")
    print(f"📊 Health: http://localhost:{port}/api/health")
    print(f"📈 Metrics: http://localhost:{port}/api/metrics")
    print("=" * 50)
    print("✅ No external dependencies required")
    print("⚡ Ultra-fast responses with mock data")
    print("🔄 CORS enabled for frontend development")
    print("=" * 50)
    print("Press Ctrl+C to stop the server")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
#!/usr/bin/env python3
"""
SecureGuard Backend Server
Run this script to start the FastAPI backend server
"""

import uvicorn
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "app"))

from app.config import settings

if __name__ == "__main__":
    print("🛡️  Starting SecureGuard Backend Server")
    print(f"   Host: {settings.HOST}")
    print(f"   Port: {settings.PORT}")
    print(f"   Debug: {settings.DEBUG}")
    print("   API Documentation: http://localhost:8000/docs")
    print("   Health Check: http://localhost:8000/health")
    print()

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )

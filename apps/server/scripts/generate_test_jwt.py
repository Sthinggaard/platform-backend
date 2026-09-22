#!/usr/bin/env python3
"""
Generate a test JWT token for UAT testing.

Uses the testing secret from .env.local to create a valid JWT token
with required claims (user_id, organization_id).
"""

import json
import sys
from datetime import datetime, timedelta

try:
    from jose import jwt
except ImportError:
    print("Error: python-jose not installed")
    print("Install with: pip install python-jose")
    sys.exit(1)

# False positive (A1 security remediation review): a labeled placeholder
# for local UAT testing only. Not deployed — apps/server/Dockerfile only
# COPYs src/alembic/alembic.ini, never scripts/, so this never ships in
# any built image, and the real app's AUTH_JWT_SECRET always comes from
# an environment variable (get_jwt_secret_bytes()), never this constant.
# Testing secret from .env.local
SECRET = "dev-test-secret"  # nosemgrep: python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret

# Create token payload with required claims
payload = {
    "sub": "1",  # user_id
    "email": "test@example.com",
    "https://risklence.com/organization_id": 1,
    "https://risklence.com/roles": ["user", "admin"],
    "https://risklence.com/permissions": ["read", "write"],
    "iat": datetime.utcnow(),
    "exp": datetime.utcnow() + timedelta(hours=24),
}

# Generate JWT using HS256
token = jwt.encode(payload, SECRET, algorithm="HS256")  # nosemgrep: python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret

print(token)

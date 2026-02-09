"""
ASGI configuration for SecureText ECC project.

This module exposes the ASGI callable as a module-level variable named `application`.

It is used for:
- Asynchronous request handling
- WebSockets
- Real-time features
- ASGI-compatible servers (Uvicorn, Daphne, Hypercorn)

Official documentation:
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

# Set the default Django settings module for ASGI
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Create the ASGI application callable
application = get_asgi_application()

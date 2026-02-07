"""
WSGI configuration for SecureText ECC project.

This module exposes the WSGI callable as a module-level variable named
`application`.

It is used by traditional WSGI servers such as:
- Gunicorn
- uWSGI
- mod_wsgi

Official documentation:
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

# Set the default Django settings module for WSGI
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Create the WSGI application callable
application = get_wsgi_application()

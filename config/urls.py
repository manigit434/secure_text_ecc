"""
URL configuration for SecureText ECC project.

This file routes incoming requests to the appropriate Django apps.
"""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    # Admin interface
    path("admin/", admin.site.urls),

    # Core application URLs
    path("", include("core.urls")),
]

"""
Application configuration for the Core app.

This configuration defines metadata for the Core application and
controls how Django initializes the app.
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """
    Core application configuration.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
    verbose_name = "Secure Core Services"

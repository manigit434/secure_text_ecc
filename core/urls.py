from django.urls import path
from . import views

app_name = "core"

urlpatterns = [
    # Public
    path("", views.public_dashboard_view, name="dashboard"),

    # Auth
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("register/", views.register_view, name="register"),
    path("check-username/", views.check_username, name="check_username"),

    # User
    path("success/", views.success_view, name="success"),
    path("mine/", views.my_submissions, name="mine"),  # ✅ updated to safe view
    path("submit/", views.submit_view, name="submit"),

    # Admin decrypt (single page)
    path(
        "admin/decrypt/<int:sub_id>/",
        views.admin_decrypt_view,
        name="admin_decrypt",
    ),
]
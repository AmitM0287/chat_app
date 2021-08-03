from django.urls import path
from auth_app import views

# URL Configuration for auth_app
app_name='auth_app'

urlpatterns = [
    path('login/', views.LoginAPIView.as_view(), name='user_login'),
    path('register/', views.RegisterAPIView.as_view(), name='user_register'),
    path('reset-password/<token>', views.ResetPasswordAPIView.as_view(), name='user_reset_password'),
    path('forgot-password/', views.ForgotPasswordAPIView.as_view(), name='user_forgot_password'),
]

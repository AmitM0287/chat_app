from django.urls import path
from auth_app import views


# URL Configuration for auth_app
app_name='auth_app'

urlpatterns = [
    path('login/', views.LoginAPIView.as_view(), name='user_login'),
    path('register/', views.RegisterAPIView.as_view(), name='user_register'),
]

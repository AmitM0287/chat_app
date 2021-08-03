from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import ValidationError

from django.conf import settings
from django.contrib.auth.models import User, auth

import jwt

from logging_config.logger import get_logger
from auth_app.serializers import LoginSerializer, RegisterSerializer, PasswordSerializer
from auth_app.utils import get_object_by_username

# Logger configuration
logger = get_logger()


class LoginAPIView(APIView):
    """
        Login API View : LoginSerializer, create token, authenticate user
    """
    def post(self, request):
        """
            This method is used for login authentication.
            :param request: It's accept username and password as parameter.
            :return: It's return response that login is successfull or not.
        """
        try:
            # Login serializer
            serializer = LoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            # Create token
            token = jwt.encode({'username': serializer.data.get('username')}, settings.SECRET_KEY, algorithm='HS256')
            # Authenticate username & password
            user = auth.authenticate(username=serializer.data.get('username'), password=serializer.data.get('password'))
            if user is not None:
                # Login successfull
                return Response({'success': True, 'message': 'Login successfull!', 'data' : {'username': serializer.data.get('username'), 'token': token}}, status=status.HTTP_200_OK)
            else:
                # Login failed
                return Response({'success': False, 'message': 'Login failed!', 'data': {'username': serializer.data.get('username')}}, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:
            logger.exception(e)
            return Response({'success': False, 'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(e)
            return Response({'success': False, 'message': 'Oops! Something went wrong! Please try again...'}, status=status.HTTP_400_BAD_REQUEST)


class RegisterAPIView(APIView):
    """
        Register API View : RegisterSerializer, check email & username already exist or not, create new user
    """
    def post(self, request):
        """
            This method is used to create new user instance.
            :param request: It's accept first_name, last_name, email, username and password as parameter.
            :return: It's return response that user created successfully or not.
        """
        try:
            # Register serializer
            serializer = RegisterSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            # Check given email is already registered or not
            if User.objects.filter(email=serializer.data.get('email')).exists():
                return Response({'success': False, 'message': 'Gven email is already registered with another user', 'data': {'email': serializer.data.get('email')}}, status=status.HTTP_400_BAD_REQUEST)
            # Check given username is already taken or not
            if User.objects.filter(username=serializer.data.get('username')).exists():
                return Response({'success': False, 'message': 'Gven username is already taken', 'data': {'username': serializer.data.get('username')}}, status=status.HTTP_400_BAD_REQUEST)
            # Create user instance
            user = User.objects.create_user(first_name=serializer.data.get('first_name'), last_name=serializer.data.get('last_name'), email=serializer.data.get('email'), username=serializer.data.get('username'), password=serializer.data.get('password'))
            user.save()
            # User registration successfull
            return Response({'success': True, 'message': 'Registration successfull!', 'data': {'username': serializer.data.get('username')}}, status=status.HTTP_200_OK)
        except ValidationError as e:
            logger.exception(e)
            return Response({'success': False, 'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(e)
            return Response({'success': False, 'message': 'Oops! Something went wrong! Please try again...'}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordAPIView(APIView):
    """
        Reset Password API View : PasswordSerializer, reset password
    """
    def put(self, request, *args,**kwargs):
        """
            This method is used to reset password for a user instance.
            :param request: It's accept token and password as parameter.
            :return: It's return response that password is updated or not.
        """
        try:
            # Getting token from URL
            token = kwargs['token']
            # Decode token
            data = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            # Get user instance according to username
            user = get_object_by_username(data.get('username'))
            # Password serializer
            serializer = PasswordSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            # Reset password
            user.set_password(serializer.data.get('password'))
            user.save()
            # Password reseted successfully
            return Response({'success': True, 'message': 'Reset password successfully!', 'data': {'username': data.get('username')}}, status=status.HTTP_200_OK)
        except User.DoesNotExist as e:
            logger.exception(e)
            return Response({'success': False, 'message': 'User does not exist!', 'data': {'username': data.get('username')}}, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:
            logger.exception(e)
            return Response({'success': False, 'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(e)
            return Response({'success': False, 'message': 'Oops! Something went wrong! Please try again...'}, status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordAPIView(APIView):
    """
        ForgotPasswordAPIView: forgot password
    """
    def post(self, request):
        """
            This method is used for fogot password of a user instance.
            :param request: It's accept username as parameter.
            :return: It's return response that reset password link send successfully or not.
        """
        try:
            # Get user instance according to username
            user = get_object_by_username(request.data.get('username'))
            # Create token
            token = jwt.encode({'username': request.data.get('username')}, settings.SECRET_KEY, algorithm='HS256')
            # Reset link
            reset_pass_link = 'http://127.0.0.1:8000/user/reset-password/' + token
            # Get user instance according to username
            return Response({'success': True, 'message': 'Email sended successfully to your registered email address for reset password!', 'data': {'username': request.data.get('username')}}, status=status.HTTP_200_OK)
        except User.DoesNotExist as e:
            logger.exception(e)
            return Response({'success': False, 'message': 'User does not exist!', 'data': {'username': request.data.get('username')}}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(e)
            return Response({'success': False, 'message': 'Oops! Something went wrong! Please try again...'}, status=status.HTTP_400_BAD_REQUEST)

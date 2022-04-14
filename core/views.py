from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import exceptions
from django.utils import timezone
import random
import string
import pyotp

from .authentication import (
    JWTAuthentication,
    create_access_token,
    create_refresh_token,
    decode_refresh_token
)
from .models import Reset, User, UserToken
from .serializers import UserSerializer


class RegisterAPIView(APIView):
    def post(self, request):
        data = request.data

        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Passwords do not match')
        
        serializer = UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if not user:
            raise exceptions.AuthenticationFailed('Invalid credentials')
        
        if not user.check_password(password):
            raise exceptions.AuthenticationFailed('Invalid credentials')

        if user.tfa_secret:
            return Response({
                'user_id': user.id
            })
        
        secret = pyotp.random_base32()
        otp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(issuer_name='DRF Auth')

        return Response({
            'user_id': user.id,
            'secret': secret,
            'otp_auth_url': otp_auth_url
        })


class TwoFactorAPIView(APIView):
    def post(self, request):
        _id = request.data['user_id']

        user = User.objects.filter(id=_id).first()

        if not user:
            raise exceptions.AuthenticationFailed('Invalid credentials')
        
        secret = user.tfa_secret if user.tfa_secret != '' else request.data['secret']

        if not pyotp.TOTP(secret).verify(request.data['code']):
            raise exceptions.AuthenticationFailed('Invalid credentials')
        
        if user.tfa_secret == '':
            user.tfa_secret = secret
            user.save()

        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        UserToken.objects.create(
            user_id=user.id,
            token=refresh_token,
            expired_at=(timezone.now() + timezone.timedelta(days=7))
        )

        response = Response()
        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)
        response.data = {
            'access': access_token
        }
        return response


class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        _id = decode_refresh_token(refresh_token)

        if not UserToken.objects.filter(user_id=_id, token=refresh_token).exists():
            raise exceptions.AuthenticationFailed('Unauthenticated')

        access_token = create_access_token(_id)
        return Response({
            'access': access_token
        })


class LogoutAPIView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie(key='refresh_token')
        refresh_token = request.COOKIES.get('refresh_token')
        UserToken.objects.filter(token=refresh_token).delete()
        response.data = {
            'message': 'Logged out'
        }
        return response


class UserAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class ForgotAPIView(APIView):
    def post(self, request):
        data = request.data
        token = ''.join([random.choice(string.ascii_lowercase + string.digits) for _ in range(10)])
        Reset.objects.create(email=data['email'], token=token)
        return Response({
            'token': token
        })


class ResetAPIView(APIView):
    def post(self, request):
        data = request.data

        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Passwords do not match')
        
        reset = Reset.objects.filter(token=data['token']).first()

        user = User.objects.filter(email=reset.email).first()

        if not user:
            raise exceptions.APIException('User does not exist')

        user.set_password(data['password'])
        user.save()
        return Response({
            'message': 'Password changed'
        })
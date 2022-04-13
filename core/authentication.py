import jwt
from django.utils import timezone
from django.conf import settings
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions


from .models import User


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if auth and len(auth) == 2:
            token = auth[1].decode('utf-8')
            _id = decode_access_token(token)
            user = User.objects.get(id=_id)
            return (user, None)

        raise exceptions.AuthenticationFailed('Unauthenticated')


def create_access_token(_id):
    return jwt.encode({
        'user_id': _id,
        'exp': timezone.now() + timezone.timedelta(seconds=30),
        'iat': timezone.now()
    }, settings.SECRET_KEY, algorithm='HS256')


def decode_access_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Unauthenticated')


def create_refresh_token(_id):
    return jwt.encode({
        'user_id': _id,
        'exp': timezone.now() + timezone.timedelta(days=7),
        'iat': timezone.now()
    }, settings.SECRET_KEY, algorithm='HS256')


def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Unauthenticated')
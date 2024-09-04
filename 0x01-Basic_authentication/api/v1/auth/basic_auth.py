#!/usr/bin/env python3
"""
Module containing class BasicAuth
inheriting from Auth and implementing
BasicAuth for REST API
"""
from api.v1.auth.auth import Auth
from typing import Optional, Tuple, TypeVar
from models.user import User
import base64


class BasicAuth(Auth):
    """
    Contains BasicAuth implementation
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> Optional[str]:
        """
        Returns the Base64 part of authorization header
        for Basic authentication
        """
        if authorization_header is None:
            return None
        if type(authorization_header) != str:
            return None
        auth_list = authorization_header.split(" ")
        if auth_list[0] != 'Basic':
            return None
        else:
            return auth_list[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> Optional[str]:
        """
        Returns decoded value of Base64 string of
        base64_authorization_header
        """
        print(base64_authorization_header)
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) != str:
            return None
        try:
            decoded = base64.b64decode(base64_authorization_header)
            print(decoded)
        except Exception as e:
            return None
        try:
            decoded = decoded.decode(encoding='utf-8')
        except Exception as e:
            return None
        return decoded

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header:
            str) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns user email and password from Base64 decoded value
        (decoded_base64_authorization_header)
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) != str:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        user_cred = decoded_base64_authorization_header.split(':')
        user_pwd = ':'.join(user_cred[1:])
        return user_cred[0], user_pwd

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> Optional[TypeVar('User')]:
        """
        Returns user instance associated with user_email and user_pwd
        """
        if user_email is None or type(user_email) != str:
            return None
        if user_pwd is None or type(user_pwd) != str:
            return None
        attributes = {'email': user_email}
        if User.count() == 0:
            return None
        users = User.search(attributes)
        if len(users) == 0:
            # print("no such email found")
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Overloads Auth, and retrieves the User instance for a request
        """
        auth_header = self.authorization_header(request)
        base_64_auth = self.extract_base64_authorization_header(auth_header)
        decoded = self.decode_base64_authorization_header(base_64_auth)
        user_cred = self.extract_user_credentials(decoded)
        user = self.user_object_from_credentials(user_cred[0], user_cred[1])
        return user

#!/usr/bin/env python3
'''Auth class'''
from flask import Flask, jsonify, abort, request
from typing import List, TypeVar


class Auth:
    '''Auth class'''
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''require auth method'''
        return False

    def authorization_header(self, request=None) -> str:
        '''authorization header method'''
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''current user method'''
        return None

#!/usr/bin/env python3
'''Auth class'''
from flask import Flask, jsonify, abort, request
from typing import List, TypeVar


class Auth:
    '''Auth class'''
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''require auth method'''
        if path is None:
            return True
        if not excluded_paths:
            return True
        normalized_path = path.rstrip('/')
        for excluded in excluded_paths:
            if excluded.endswith('*'):
                base_path = excluded[:-1].rstrip('/')
                if normalized_path.startswith(base_path):
                    return False
            else:
                if normalized_path == excluded.rstrip('/'):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        '''authorization header method'''
        if request is not None:
            return request.headers['Authorization']
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''current user method'''
        return None

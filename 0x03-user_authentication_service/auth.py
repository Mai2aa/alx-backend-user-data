#!/usr/bin/env python3
'''Hash password'''
import bcrypt


def _hash_password(password: str) -> bytes:
    '''Hash password using bcrypt'''
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

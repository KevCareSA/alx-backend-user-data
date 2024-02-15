#!/usr/bin/env python3

"""
Manages the API authentication.

"""
from os import environ
from flask import request
from typing import List, TypeVar


class Auth:
    """ a class to manage the API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ returns True if the path is not in the list of strings
            excluded_paths
        """
        if (path is None or excluded_paths is None or excluded_paths == []):
            return True

        new_path = f"{path}/" if path[-1] != '/' else path

        for p in excluded_paths:
            if p[-1] == "*" and path.startswith(p[:-1]):
                return False
            elif (new_path == p):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """the Flask request object"""
        if (request is None or request.headers.get("Authorization") is None):
            return None

        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):  # type: ignore
        """the Flask request object"""
        return None

    def session_cookie(self, request=None):
        """ returns a cookie value from a request
        """
        if (request is None):
            return None
        return request.cookies.get(environ.get("SESSION_NAME"))

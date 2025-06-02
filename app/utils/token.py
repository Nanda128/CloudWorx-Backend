from functools import wraps
from typing import Callable

import jwt
from flask import current_app, request

from app.models.user import UserLogin


def token_required(f: Callable) -> Callable:
    """Check if the request has a valid JWT token"""

    @wraps(f)
    def decorated(*args: object, **kwargs: object) -> object:
        error_response = None

        auth_header = request.headers.get("Authorization", "")
        if not auth_header:
            error_response = ({"message": "Token is missing!"}, 401)
        else:
            parts = auth_header.split(" ")
            auth_header_parts = 2
            if len(parts) != auth_header_parts or parts[0] != "Bearer":
                error_response = ({"message": "Authorization header must be in the format: Bearer <token>"}, 401)
            else:
                token = parts[1]
                try:
                    jwt_secret = current_app.config["JWT_SECRET_KEY"]
                    if not jwt_secret:
                        error_response = ({"message": "JWT secret key is not set in environment variables!"}, 500)
                    else:
                        data = jwt.decode(token, jwt_secret, algorithms=["HS256"])
                        current_user = UserLogin.query.filter_by(id=data["user_id"]).first()
                        if not current_user:
                            error_response = ({"message": "User not found!"}, 401)
                        else:
                            return f(current_user, *args, **kwargs)
                except jwt.ExpiredSignatureError:
                    error_response = ({"message": "Token has expired!"}, 401)
                except jwt.InvalidTokenError:
                    error_response = ({"message": "Token is invalid!"}, 401)

        return error_response

    return decorated

from functools import wraps  # noqa: INP001
from typing import Callable

import jwt
from flask import current_app, request

from app.models.user import UserLogin


def token_required(f: Callable) -> Callable:
    """Check if the request has a valid JWT token"""

    @wraps(f)
    def decorated(*args: object, **kwargs: object) -> object:
        token = request.headers.get("Authorization", "").split(" ")[1] if "Authorization" in request.headers else None
        if not token:
            return {"message": "Token is missing!"}, 401
        try:
            jwt_secret = current_app.config["JWT_SECRET_KEY"]
            if not jwt_secret:
                return {"message": "JWT secret key is not set in environment variables!"}, 500
            data = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            current_user = UserLogin.query.filter_by(id=data["user_id"]).first()
            if not current_user:
                return {"message": "User not found!"}, 401
        except jwt.ExpiredSignatureError:
            return {"message": "Token has expired!"}, 401
        except jwt.InvalidTokenError:
            return {"message": "Token is invalid!"}, 401
        return f(current_user, *args, **kwargs)

    return decorated

from rest_framework.response import Response
from rest_framework import status
from functools import wraps
from .models import Permission_role, UserRole
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
import jwt


class UnauthorizedError(Exception):
    def __init__(self, message="Пользователь не авторизован"):
        super().__init__(message)
        self.status_code = status.HTTP_401_UNAUTHORIZED


class AccessDeniedError(Exception):
    def __init__(self, message="Доступ запрещен не соответсвующих прав"):
        super().__init__(message)
        self.status_code = status.HTTP_403_FORBIDDEN


EXCEPT = (UnauthorizedError, AccessDeniedError)


# функция для проверки имеет ли текущий пользователь право выполнять определенные действия
def get_user_permissions(user) -> dict:
    """Возврращает словарь с имеющимися у пользователя правами"""
    if (
        not user
    ):  # если пользователь не указан возвращаем пустой словарь что эквивалентно отсутсвию прав
        return {}

    user_roles = UserRole.objects.filter(user=user).values_list(
        "role_id", flat=True
    )  # получаем роли текущего пользователя
    rules = Permission_role.objects.filter(
        role_id__in=user_roles
    )  # получаем права необходимы для доступа

    permissions = {
        "can_read": False,
        "can_read_all": False,
        "can_create": False,
        "can_update_all": False,
        "can_update": False,
        "can_delete": False,
        "can_delete_all": False,
    }
    # формируем итоговый словарь прав доступа
    for rule in rules:
        permissions["can_read"] = permissions["can_read"] or rule.can_read
        permissions["can_read_all"] = permissions["can_read_all"] or rule.can_read_all
        permissions["can_create"] = permissions["can_create"] or rule.can_create
        permissions["can_update"] = permissions["can_update"] or rule.can_update
        permissions["can_update_all"] = (
            permissions["can_update_all"] or rule.can_update_all
        )
        permissions["can_delete"] = permissions["can_delete"] or rule.can_delete
        permissions["can_delete_all"] = (
            permissions["can_delete_all"] or rule.can_delete_all
        )

    return permissions


# проверка имеет ли пользователь определнную роль
def has_role(user, role_name: str) -> bool:
    res: bool = False
    if not user:
        return res
    res = UserRole.objects.filter(user=user, role__name=role_name).exists()
    return res


def require_auth(view_func):
    def wrapper(self, request, *args, **kwargs):
        if not request.current_user:
            return Response(
                {"error": "Не авторизован"}, status=status.HTTP_401_UNAUTHORIZED
            )
        return view_func(self, request, *args, **kwargs)

    return wrapper


def generate_jwt_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "exp": timezone.now() + timedelta(hours=settings.JWT_EXPIRATION_HOURS),
        "iat": timezone.now(),
    }
    return jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def decode_jwt_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

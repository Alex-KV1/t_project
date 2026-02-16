from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.request import Request
from users.models import User
import users.permissions as Permissions
from SimulateBusinessWorks import gen_mock

# вычесления проихсодит между запусками всего приложения
# LEN_USERS = User.objects.count() # получение числа зарегистрированных пользователей
prod = gen_mock.generate_mock_products(20)
shops = gen_mock.generate_mock_shops(15)


def check_authorization(request: Request) -> User:
    session_token = request.COOKIES.get("session_id")
    user = User.objects.filter(session_tk=session_token).first()
    if not (session_token and user):
        raise Permissions.UnauthorizedError
    return user


def check_permission(user: User, permission: str):
    """Проверять есть ли у пользователя определенное право"""
    if not user:
        raise Permissions.UnauthorizedError

    permissions = Permissions.get_user_permissions(user)  # подумать над логикой
    if not permissions.get(permission, False):
        raise Permissions.AccessDeniedError


class ProductListView(APIView):

    def get(self, request: Request):
        try:
            user = check_authorization(request)
            permissions = Permissions.get_user_permissions(user)
            if permissions.get("can_read_all"):
                return Response({"product": prod, "access": "can_read_all"})

            elif permissions.get("can_read"):
                user_products = [item for item in prod if item["owner_id"] == user.id]
                return Response({"products": user_products, "access": "can_read"})

            return Response(
                {"error": "Доступ запрещен"}, status=status.HTTP_403_FORBIDDEN
            )

        except Permissions.EXCEPT as err:
            return Response({"error": f"{repr(err)}"}, status=err.status_code)

    def post(self, request):
        try:
            user = check_authorization(request)
            check_permission(user, "can_create")

            new_product = {
                "id": len(prod) + 1,
                "name": request.data.get("name", "Новый товар"),
                "price": request.data.get("price", 0),
                "owner_id": user.id,
            }
            return Response(
                {"message": "Товар успешно добавлен", "prod": new_product},
                status=status.HTTP_201_CREATED,
            )
        except Permissions.EXCEPT as err:
            return Response({"error": f"{repr(err)}"}, status=err.status_code)


class ShopListView(APIView):
    def get(self, request):
        try:
            user = check_authorization(request)

            permissions = Permissions.get_user_permissions(user)
            if permissions.get("can_read_all"):
                return Response({"shops": shops, "access": "can_read_all"})

            elif permissions.get("can_read"):
                user_shops = [item for item in shops if item["owner_id"] == user.id]
                return Response({"shops": user_shops, "access": "can_read"})
            raise Permissions.AccessDeniedError
        except Permissions.EXCEPT as err:
            return Response({"error": f"{repr(err)}"}, status=err.status_code)

    def post(self, request):
        try:
            user = check_authorization(request)
            check_permission(user, "can_create")
            new_shop = {
                "id": len(shops) + 1,
                "name": request.data.get("name", "Новый магазин"),
                "address": request.data.get("address", ""),
                "owner_id": user.id,
            }
            return Response(
                {"message": "Магазин был успешно добавлен", "shop": new_shop},
                status=status.HTTP_201_CREATED,
            )
        except Permissions.EXCEPT as err:
            return Response({"error": f"{repr(err)}"}, status=err.status_code)

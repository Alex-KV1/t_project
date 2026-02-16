from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from rest_framework import generics, permissions, status
from .models import User, Role, UserRole
from rest_framework.response import Response
from .serializers import (
    UserRegistrationSerializer,
    UserRoleSerializer,
    UserSerializer,
    BaseUserSerializer,
    UserUpdatePasswordSerializer,
    SetRoleSerializer,
)
from rest_framework.views import APIView
from rest_framework.request import Request
from users.permissions import generate_jwt_token


@login_required(login_url="/api/login/")  # или '/auth/register/'
def home(request):
    return HttpResponse("Добро пожаловать на главную страницу!")


class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            default_role = Role.objects.filter(name="user").first()
            if default_role:
                UserRole.objects.create(user=user, role=default_role)
            token = generate_jwt_token(user.id)
            return Response(
                {
                    "detail": "Регистрация прошла успешна",
                    "user": UserSerializer(user).data,
                    "token": token,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(generics.GenericAPIView):
    serializer_class = BaseUserSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request: Request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({"detail": f"Пользователь {request.user.get_username()}"})
        return Response(
            {"detail": "Пожалуйста авторизуйтесь."}, status=status.HTTP_401_UNAUTHORIZED
        )

    def post(self, request: Request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response(
                {
                    "detail": f"Пользователь {request.user.get_username()} уже залогинен для входа под другим именем необходимо выполнит логаут"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )  # Уведомление о том, что пользователь уже залогинен

        serializer = BaseUserSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response(
                    {"error": "Неверный email или пароль"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not user.is_active:
                return Response(
                    {"error": "Аккаунт деактивирован"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not user.check_password(password):
                return Response(
                    {"error": "Неверный email или пароль"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            token = generate_jwt_token(user.id)

            session_token = user.create_session()

            response = Response(
                {
                    "message": "Вход выполнен успешно",
                    "user": UserSerializer(user).data,
                    "token": token,
                }
            )

            response.set_cookie(
                "JWT", token, expires=user.exp_at, httponly=True, samesite="Lax"
            )
            response.set_cookie(
                "session_id",
                session_token,
                expires=user.exp_at,
                httponly=True,
                samesite="Lax",
            )
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Логика логаута
class UserLogoutView(APIView):

    # для логаута по гет запросу
    def get(self, requset: Request, *args, **kwargs):
        return self.logout_user(request=requset)

    # для логаута по пост запросу
    def post(self, request: Request, *args, **kwargs):
        return self.logout_user(request=request)

    def logout_user(self, request: Request):
        if not request.COOKIES.get("session_id"):
            return Response(
                {"error": "Ошибка вы не авторизованы"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        session_token = request.COOKIES.get("session_id")
        u_name = User.objects.filter(session_tk=session_token).first().name
        if session_token:
            User.objects.filter(session_tk=session_token).update(
                session_tk=None, exp_at=None, token_created_at=None
            )
        response = Response(
            {"detail": f"Пользователь {u_name} вышел из системы."},
            status=status.HTTP_200_OK,
        )
        response.delete_cookie("session_id")
        return response


# Обновление информации пользователя
class UserUpdateView(APIView):
    serializer_class = UserUpdatePasswordSerializer

    def get(self, request: Request, *args, **kwargs):
        if not request.COOKIES.get("session_id"):
            return Response(
                {"error": "Ошибка вы не авторизованы"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        session_token = request.COOKIES.get("session_id")
        user = User.objects.filter(session_tk=session_token).first()
        if not user:
            return Response(
                {"error": "Ошибка: пользователь не найден"},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(
            {
                "message": "Вход выполнен успешно",
                "user": UserSerializer(user).data,
            }
        )

    def put(self, request):
        if not request.COOKIES.get("session_id"):
            return Response(
                {"error": "Ошибка вы не авторизованы"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        session_token = request.COOKIES.get("session_id")
        user = User.objects.filter(session_tk=session_token).first()
        serializer = UserUpdatePasswordSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": f"Профиль  пользователя {user.name} обновлен"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Удаление пользователя
class UserDeleteView(APIView):

    def get(
        self,
        request: Request,
    ):
        if not request.COOKIES.get("session_id"):
            return Response(
                {"error": "Ошибка вы не авторизованы"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        session_token = request.COOKIES.get("session_id")
        user = User.objects.filter(session_tk=session_token).first()

        return Response(
            {
                "detail": "Страница удаления пользователя",
                "user": UserSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )

    def delete(self, request):
        if not request.COOKIES.get("session_id"):
            return Response(
                {"error": "Ошибка вы не авторизованы"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        session_token = request.COOKIES.get("session_id")
        user = User.objects.filter(session_tk=session_token).first()
        user.is_active = False
        if session_token:
            user.token_created_at = user.exp_at = user.session_tk = None
        user.save()
        response = Response(
            {"message": f"Аккаунт пользователя {user.name} деактивирован"}
        )
        response.delete_cookie("session_id")
        return response


#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [permissions.IsAuthenticated]

    def has_access(self, user):
        return user.is_staff


class UserRoleUpdateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(
                {"detail": "Пользователь не найден."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = UserRoleSerializer(user, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()  # Обновление пользователя
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# administrate views ------------------------------------------------------------------------
from .serializers import AdminViewRole
from SimulateBusinessWorks.views import check_authorization
from .permissions import UnauthorizedError


class RoleListView(APIView):
    def get(self, request):
        try:
            user = check_authorization(request)
            if user.is_staff:
                return Response(AdminViewRole(Role.objects.all(), many=True).data)
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )

    def post(self, request):
        user = check_authorization(request)
        try:
            if user.is_staff:
                serializer = AdminViewRole(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )


class RoleDetailView(APIView):
    def get(self, request, pk):
        try:
            user = check_authorization(request)
            if user.is_staff:
                return Response(AdminViewRole(Role.objects.get(pk=pk)).data)
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )
        except Role.DoesNotExist:
            return Response(
                {"error": "Роль не найдена"}, status=status.HTTP_404_NOT_FOUND
            )
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )

    def put(self, request, pk):
        try:
            user = check_authorization(request)
            if user.is_staff:
                role = Role.objects.get(pk=pk)
                serializer = AdminViewRole(role, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Role.DoesNotExist:
            return Response(
                {"error": "Роль не найдена"}, status=status.HTTP_404_NOT_FOUND
            )
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )

    def delete(self, request, pk):
        try:
            user = check_authorization(request)
            if user.is_staff:
                Role.objects.get(pk=pk).delete()
            return Response(
                {"detail": "Роль удалена"}, status=status.HTTP_204_NO_CONTENT
            )
        except Role.DoesNotExist:
            return Response(
                {"error": "Роль не найдена"}, status=status.HTTP_404_NOT_FOUND
            )
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )


class AdministrateUsersView(APIView):

    def get(self, request):
        try:
            user = check_authorization(request)
            if user.is_staff:
                res = []
                # user_roles = UserRole.objects.select_related('user', 'role').all()
                users = User.objects.all()
                for user in users:
                    user_role = UserRole.objects.filter(user=user).first()
                    role_name = user_role.role.name if user_role else "Нет роли"

                    res.append(
                        {
                            "id": user.id,
                            "email": user.email,
                            "name": user.name,
                            "rol": role_name,
                        }
                    )
                return Response(res)
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )

    def post(self, request):
        try:
            serializer = UserRoleSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )


class AdministrateUser(APIView):

    def get(self, request, pk):
        try:
            user = check_authorization(request)
            if user.is_staff:
                user_instance = User.objects.filter(id=pk).first()
                if user_instance:
                    user_role = UserRole.objects.filter(user=user_instance).first()
                    role_name = user_role.role.name if user_role else "Нет роли"
                    roles = Role.objects.all()
                    return Response(
                        {
                            "id": user_instance.id,
                            "email": user_instance.email,
                            "name": user_instance.name,
                            "role": role_name,
                            "roles_exists": AdminViewRole(roles, many=True).data,
                        }
                    )
                return Response({"detail": "Пользователь не найден"})

            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )

    def put(self, request, pk):
        try:
            user = check_authorization(request)
            if user.is_staff:
                user_role = UserRole.objects.filter(user__id=pk).first()
                if not user_role:
                    return Response(
                        {"error": "Роль пользователя не найдена"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                serializer = SetRoleSerializer(instance=user_role, data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(
                        {"detail": "Роль пользователя успеншно изменена"},
                        status=status.HTTP_200_OK,
                    )
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )
        except UnauthorizedError:
            return Response(
                {"error": "Отказано в доступе"}, status=status.HTTP_403_FORBIDDEN
            )

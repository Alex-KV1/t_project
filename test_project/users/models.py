from django.db import models
import bcrypt
import uuid
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

# Create your models here.


# Модель пользователя.
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, verbose_name="email")
    name = models.CharField(max_length=255, verbose_name="Пользователь")
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Создан")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Обновлен")
    password = models.CharField(max_length=255, verbose_name="пароль")
    session_tk = models.CharField(
        null=True, max_length=255, unique=True, verbose_name="Токен сессии"
    )
    exp_at = models.DateTimeField(null=True, verbose_name="Время истечения")
    token_created_at = models.DateTimeField(
        null=True, auto_now_add=True, verbose_name="Дата создания токена"
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "password"]

    class Meta:
        db_table = "users"
        verbose_name = "Пользователь"
        verbose_name_plural = "Пользователи"

    def set_password(self, password: str):
        s_t = bcrypt.gensalt()
        self.password = bcrypt.hashpw(password.encode("utf-8"), s_t).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode("utf-8"), self.password.encode("utf-8"))

    def create_session(self):
        session_token = str(uuid.uuid4())

        from datetime import timedelta
        from django.utils import timezone

        expires_at = timezone.now() + timedelta(days=1)
        self.session_tk = session_token
        self.token_created_at = timezone.now()
        self.last_login = self.token_created_at
        self.exp_at = expires_at
        self.save()
        return session_token

    def __str__(self):
        return self.email


# Модель описания роли
class Role(models.Model):
    name = models.CharField(max_length=100, unique=True, verbose_name="Название роли")
    description = models.TextField(verbose_name="Описание")

    class Meta:
        db_table = "roles"
        verbose_name = "Роль"
        verbose_name_plural = "Роли"

    def __str__(self):
        return self.name


# Модель разрешений.
class Permission_role(models.Model):
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name="Permission_role", null=True
    )

    can_read = models.BooleanField(default=False, verbose_name="Разрешение на чтение")
    can_read_all = models.BooleanField(
        default=False, verbose_name="Разрешение на чтение всех"
    )
    can_create = models.BooleanField(
        default=False, verbose_name="Разрешение на создание"
    )
    can_update = models.BooleanField(
        default=False, verbose_name="Разрешение на обновление"
    )
    can_update_all = models.BooleanField(
        default=False, verbose_name="Разрешение на обновление всех"
    )
    can_delete = models.BooleanField(
        default=False, verbose_name="Разрешение на удаление"
    )
    can_delete_all = models.BooleanField(
        default=False, verbose_name="Разрешение на удаление любых записей"
    )

    class Meta:
        db_table = "permission_role"
        verbose_name = "Права доступа"
        unique_together = ["role"]

    def __str__(self):
        return f"{self.role.name} : {self.business_element.name}"


# Модель описывает связь между пользователями и ролями.
class UserRole(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="id_user",
        verbose_name="ИД пользователя",
    )
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name="id_roles", verbose_name="ИД Роли"
    )

    class Meta:
        db_table = "user_role"

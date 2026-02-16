from django.core.management.base import BaseCommand
from users.models import Role, Permission_role, User, UserRole


class Command(BaseCommand):

    def handle(self, *args, **options):
        # Роли
        roles = [
            {"name": "Admin", "description": "Администратор системы"},
            {"name": "Manager", "description": "Менеджер"},
            {"name": "User", "description": "Пользователь"},
        ]

        for role in roles:
            Role.objects.get_or_create(**role)

        # пользователи
        users = [
            {
                "email": "admin@mail.ru",
                "name": "Admin",
                "password": "1",
                "role": "Admin",
            },
            {
                "email": "manag@mail.ru",
                "name": "Manager",
                "password": "1",
                "role": "Manager",
            },
            {
                "email": "manag1@mail.ru",
                "name": "Manager_2",
                "password": "1",
                "role": "Manager",
            },
            {
                "email": "manag2@mail.ru",
                "name": "Manager_3",
                "password": "1",
                "role": "Manager",
            },
            {"email": "user@mail.ru", "name": "User", "password": "1", "role": "User"},
        ]

        for user_data in users:
            user, created = User.objects.get_or_create(
                email=user_data["email"],
                defaults={
                    "name": user_data["name"],
                    "is_staff": True if user_data["role"] == "Admin" else False,
                    "is_active": True,
                },
            )
            # Устанавливаем пароль
            user.set_password(user_data["password"])
            user.save()

            # Назначаем роль пользователю
            role = Role.objects.get(name=user_data["role"])
            UserRole.objects.get_or_create(user=user, role=role)

        # Назначаем права для каждой роли
        permission_settings = {
            "Admin": {
                "can_read": True,
                "can_create": True,
                "can_update": True,
                "can_delete": True,
                "can_read_all": True,
                "can_update_all": True,
                "can_delete_all": True,
            },
            "Manager": {
                "can_read": True,
                "can_create": True,
                "can_update": True,
                "can_delete": False,
                "can_read_all": False,
                "can_update_all": False,
                "can_delete_all": False,
            },
            "User": {
                "can_read": True,
                "can_create": False,
                "can_update": False,
                "can_delete": False,
                "can_read_all": False,
                "can_update_all": False,
                "can_delete_all": False,
            },
        }

        for role_name, permissions in permission_settings.items():
            role = Role.objects.get(name=role_name)
            # business_element = BusinessElement.objects.first()
            permission_role, created = Permission_role.objects.get_or_create(role=role)

            for perm_name, perm_value in permissions.items():
                setattr(permission_role, perm_name, perm_value)
            permission_role.save()

        self.stdout.write(
            self.style.SUCCESS("Успешно заполнены пользователи, роли и права.")
        )

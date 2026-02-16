from rest_framework import serializers
from .models import User, Role, UserRole


class BaseUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        model = User
        fields = ["email", "password"]


class UserRegistrationSerializer(BaseUserSerializer):
    password_confirm = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "password_confirm"]

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "Пользователь с таким email уже существует"
            )
        return value

    def validate(self, data):
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Пароли не совпадают"}
            )
        return data

    def create(self, validated_data):
        validated_data.pop("password_confirm")
        user = User(**validated_data)
        user.set_password(validated_data.pop("password"))
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):
    name = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = ["id", "email", "name", "is_active", "created_at"]
        read_only_fields = ["id", "email", "is_active", "created_at"]


class UserUpdatePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(min_length=1, write_only=True, required=False)

    class Meta:
        model = User
        fields = [
            "password",
        ]

    # установка нового пароля
    def update(self, instance: User, validated_data):
        instance.set_password(validated_data["password"])
        instance.save()
        return instance


class UserRoleSerializer(serializers.ModelSerializer):
    role = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(), required=False
    )

    class Meta:
        model = User
        fields = ["id", "email", "name", "role"]
        extra_kwargs = {"password": {"write_only": True}}

    def update(self, instance, validated_data):
        role_data = validated_data.pop("role", None)

        instance.email = validated_data.get("email", instance.email)
        instance.name = validated_data.get("name", instance.name)

        if role_data:
            instance.role = role_data

        instance.save()
        return instance


class AdminViewRole(serializers.ModelSerializer):
    id_roles = serializers.IntegerField(source="id")

    class Meta:
        model = Role
        fields = ["id_roles", "name", "description"]


class SetRoleSerializer(serializers.ModelSerializer):
    id_roles = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(), source="role"
    )

    class Meta:
        model = UserRole
        fields = ["id_roles"]

    def update(self, instance: UserRole, validated_data: dict):
        role: Role = validated_data.get("role")
        if role:
            if role and role.name == "Admin":
                instance.user.is_staff = True
            else:
                instance.user.is_staff = False
            instance.role = role
        instance.save()
        return instance

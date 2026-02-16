from django.contrib import admin
from .models import User, Role, Permission_role, UserRole

# Register your models here.

# @admin.register(User)
# class UserAdmin(admin.ModelAdmin):
#     list_display = ('name', 'email', 'updated_at','created_at')
#     search_fields = ('name',)

# @admin.register(Permission)
# class UserManagerAdmin(admin.ModelAdmin):
#     list_display = [
#         'name',
#         'description',
#         'can_read',
#         'can_read_all',
#         'can_create',
#         'can_update',
#         'can_update_all',
#         'can_delete',
#         'can_delete_all',
#     ]


# @admin.register(Role)
# class UserManagerAdmin(admin.ModelAdmin):
#     list_display = ('name', 'description')
#     search_fields = ('name',)


# @admin.register(UserRole)
# class UserManagerAdmin(admin.ModelAdmin):
#     list_display = ('user', 'role')
#     search_fields = ('name',)


# @admin.register(RolePermission)
# class UserManagerAdmin(admin.ModelAdmin):
#     list_display = ('role', 'permission')
#     search_fields = ('role',)

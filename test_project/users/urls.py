from django.urls import path
from .views import (
    UserRegistrationView,
    UserLoginView,
    UserLogoutView,
    UserUpdateView,
    UserDeleteView,
    RoleListView,
    AdministrateUsersView,
    AdministrateUser,
)

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="user-registration"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("update/", UserUpdateView.as_view(), name="user-update"),
    path("delete/", UserDeleteView.as_view(), name="user-delete"),
    path("view_role/", RoleListView.as_view(), name="Role-List-View"),
    path("view_users/", AdministrateUsersView.as_view(), name="adm-users"),
    path("view_users/<int:pk>/", AdministrateUser.as_view(), name="adm-user-id"),
]

from django.urls import path
from .views import ProductListView, ShopListView

urlpatterns = [
    path("api/mock_list/", ProductListView.as_view()),
    path("api/mock_shop/", ShopListView.as_view()),
]

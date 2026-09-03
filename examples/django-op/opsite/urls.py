from django.urls import path

from op import views

urlpatterns = [
    path(".well-known/openid-configuration", views.discovery),
    path("jwks", views.jwks),
    path("authorization", views.authorization),
    path("token", views.token),
    path("userinfo", views.userinfo),
]

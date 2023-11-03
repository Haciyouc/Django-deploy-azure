"""
URL configuration for ssad project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from app import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',views.Index,name='Index'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('login_nocaptha/', views.Login_nocaptha, name="login_nocaptha"),
    path('home/',views.index,name='home'),
    path('logout/',views.logout_view,name='logout'),
    path('attaque_dictionnaire/', views.attaque_dictionnaire_requests, name='attaque_dictionnaire'),
    path('attaque_dictionnaire_un_zero_3char_requests/', views.attaque_dictionnaire_un_zero_3char_requests, name='attaque_dictionnaire_un_zero_3char_requests'),
    path('attaque_brute_force_number_requests/', views.attaque_brute_force_number_requests, name='attaque_brute_force_number_requests'),
    path('attaque_brute_force_un_zero_3char_requests/', views.attaque_brute_force_un_zero_3char_requests, name='attaque_brute_force_un_zero_3char_requests'),
    path('attaque_brute_force_all_char_requests/', views.attaque_brute_force_all_char_requests, name='attaque_brute_force_all_char_requests'),
    path('Steganography_encode/', views.Steganography_encode, name='Steganography_encode'),
    path('Steganography_decode/', views.Steganography_decode, name='Steganography_decode'),
]

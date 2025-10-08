from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('oauth/<provider>/', views.oauth_redirect, name='oauth_redirect'),
    path('accounts/oauth-callback/', views.oauth_callback, name='oauth_callback'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
]


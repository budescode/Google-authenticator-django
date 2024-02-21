
from django.urls import path
from . import views
from .views import *
app_name='userurl' 
urlpatterns = [
    
    path('', views.homeView, name='index'),
    path('signup/', views.signupView, name='signup'),
    path('login/', views.loginView, name='login'),
    path('verify-otp/', views.verifyOtp, name='verify_otp'),
    path('logout/', views.logoutUser, name='logout'),
    
    
] 
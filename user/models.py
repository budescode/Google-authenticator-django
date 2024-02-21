from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.contrib.auth import get_user_model
import uuid
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from datetime import date
from django_otp.plugins.otp_totp.models import TOTPDevice



class CustomUser(AbstractUser):
    fullname = models.CharField(max_length=50, default='')
    email = models.EmailField(unique=True)
    authenticator_secret = models.TextField(blank=True, null=True)
    def __str__(self):
        return self.email



class EmailTOTPDevice(TOTPDevice, models.Model):
    email = models.EmailField(unique=True)   
    def __str__(self):
        return self.email
    

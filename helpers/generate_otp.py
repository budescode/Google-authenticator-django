import re
from user.models import EmailTOTPDevice
from django.contrib.auth import get_user_model
User = get_user_model()


def generate_totp_qr_code(email):
    user = User.objects.get(email__iexact=email)
    totp_device, created = EmailTOTPDevice.objects.get_or_create(email=user.email, user=user, defaults={'confirmed': True})
    name = f'Django Auth: {email}'
    modified_otp_uri = re.sub(r'otpauth://totp/[^?]+', f'otpauth://totp/{name}', totp_device.config_url)
    extract_secret(modified_otp_uri)
    return modified_otp_uri

def verify_otp(email, code):
    user = User.objects.get(email__iexact=email)
    totp_device, created = EmailTOTPDevice.objects.get_or_create(email=user.email, user=user)
    return  totp_device.verify_token(code)

def extract_secret(uri):
    secret_match = re.search(r"secret=(.*?)(&|$)", uri)
    secret = secret_match.group(1)
    return secret

from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from helpers.generate_otp import extract_secret, generate_totp_qr_code, verify_otp
from .models import *
from django.contrib.auth.models import User


User = get_user_model()

def homeView(request):
    return render(request, 'index.html')

def signupView(request):
    referralcode = request.GET.get('referralcode', '')
    if request.method == "POST": 
        fullname = request.POST.get('fullname')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")        
        if User.objects.filter(email__iexact=email).exists():
            messages.error(request, 'Email already taken')
            return redirect('userurl:signup')
        elif password1 != password2:
            messages.error(request, 'Passwords do not match')
            return redirect('userurl:signup')
        else:
            User.objects.create_user(username=email, password=password1,fullname=fullname,  email=email)

            messages.success(request, 'Registration successful, verify your OTP')


            
            return redirect('userurl:login')
    return render(request, 'signup.html' , {'referralcode':referralcode})

def loginView(request):    
    
    if request.method == "POST": 
        email = request.POST.get("email")
        password = request.POST.get("password")
        try:
            qs = User.objects.get(email__iexact=email)
        except CustomUser.DoesNotExist:
            messages.error(request, 'Invalid Credentials')
            return render(request, 'signin.html')
        
        user = authenticate(request, username=qs.username, password=password)
        
        if user is not None:
            secret = ''
            secret_stored = False 
            #used to know if the secret has been stored before or not so that we can display the qr code in frontend or not

            if user.authenticator_secret==None or user.authenticator_secret == '':                
                qs = generate_totp_qr_code(user.email)
                secret = extract_secret(qs)
                
            else:
                secret_stored = True
            
           
            return render(request, 'verify.html', {'qs':qs, 'email':email, 'secret_stored':secret_stored, 'secret':secret})

    return render(request, 'signin.html')

 
def verifyOtp(request):
    if request.method == 'POST':
        otpcode = request.POST.get('otp')
        email = request.POST.get('email')
        
        verify  = verify_otp(email, otpcode)
        if verify == False:
            messages.error(request, 'Invalid Code')
            return redirect('userurl:login')


                
        user = User.objects.get(email__iexact=email)
        login(request, user)     
        if user.authenticator_secret==None or user.authenticator_secret == '':                
            qs = generate_totp_qr_code(user.email)
            secret = extract_secret(qs)
            user.authenticator_secret = secret 
            user.save()
           

        return redirect('userurl:index')
        
    return redirect('userurl:login')        
    
    
def logoutUser(request):
	logout(request)
	return redirect('/login/')

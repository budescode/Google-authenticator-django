from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from helpers.generate_otp import extract_secret, generate_totp_qr_code, verify_otp
from user.forms import LoginForm, RegistrationForm
from .models import *


User = get_user_model()

def homeView(request):
    return render(request, 'index.html')

def signupView(request):
    form = RegistrationForm() 
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        password = request.POST['password']
        if form.is_valid():
            user = form.save()  
            user.set_password(password)  
            user.save()    
            messages.success(request, 'Registration successful')            
            return redirect('userurl:login')
    return render(request, 'signup.html', {'form':form})


def loginView(request):    
    form = LoginForm()
    print("checking lignd.d.d.d.d")
    if request.method == 'POST':
        print("yes it is post!")
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            print(username, password, "printed..")
            user = authenticate(username=username, password=password)

            if user is not None:
                secret = ''
                secret_stored = False 

                #used to know if the secret has been stored before or not so that we can display the qr code in frontend or not

                if user.authenticator_secret==None or user.authenticator_secret == '':                
                    qs = generate_totp_qr_code(user.email)
                    secret = extract_secret(qs)
                    
                else:
                    secret_stored = True               
            
                return render(request, 'verify.html', {'qs':qs, 'email':user.email, 'secret_stored':secret_stored, 'secret':secret})

    return render(request, 'signin.html', {'form':form})

    


 
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
        messages.success(request, 'Authentication Successful')          

        return redirect('userurl:index')
        
    return redirect('userurl:login')        
    
    
def logoutUser(request):
	logout(request)
	return redirect('/login/')

from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
import requests
import jwt as pyjwt
import requests

from django.conf import settings

GOOGLE_CLIENT_ID = settings.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET = settings.GOOGLE_CLIENT_SECRET
# LINKEDIN_CLIENT_ID = settings.LINKEDIN_CLIENT_ID
# LINKEDIN_CLIENT_SECRET = settings.LINKEDIN_CLIENT_SECRET
REDIRECT_URI = settings.REDIRECT_URI


def login_view(request):
    return render(request, 'login/login.html')

def oauth_redirect(request, provider):
    request.session['provider'] = provider
    scopes = {
        'google': 'openid email profile',
        "linkedin": "openid profile email"
    }
    urls = {
        'google': (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={GOOGLE_CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={scopes['google'].replace(' ', '%20')}&provider=google"
        ),
        # 'linkedin': (
        #     f"https://www.linkedin.com/oauth/v2/authorization?"
        #     f"client_id={LINKEDIN_CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={scopes['linkedin'].replace(' ', '%20')}&provider=linkedin"
        # )
    }
    return redirect(urls[provider])

def oauth_callback(request):
    code = request.GET.get('code')
    provider = request.session.get('provider')
    if not code or provider not in ['google', 'linkedin']:
        return redirect('login')

    if provider == "google":
        token_r = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                'code': code,
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'redirect_uri': REDIRECT_URI,
                'grant_type': 'authorization_code'
            }
        )
        access_token = token_r.json().get('access_token')
        userinfo = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        ).json()
        name = userinfo.get('name', '')
        email = userinfo.get('email', '')
    # else:  
    #     token_r = requests.post(
    #     "https://www.linkedin.com/oauth/v2/accessToken",
    #     data={
    #         "code": code,
    #         "client_id": LINKEDIN_CLIENT_ID,
    #         "client_secret": LINKEDIN_CLIENT_SECRET,
    #         "redirect_uri": REDIRECT_URI,
    #         "grant_type": "authorization_code"
    #     }
    # )
    # token_data = token_r.json()
    # id_token = token_data.get("id_token")

    # if not id_token:
    #     return HttpResponse("Login with LinkedIn failed: no id_token returned.", status=400)

    # claims = pyjwt.decode(id_token, options={"verify_signature": False})

    # name = claims.get("name") 
    # email = claims.get("email") 

    user, _ = User.objects.get_or_create(
        username=email,
        defaults={"first_name": name, "email": email}
    )
    login(request, user)
    return redirect("dashboard")


@login_required
def dashboard(request):
    return render(request, 'login/homepage.html', {'user': request.user})

def logout_view(request):
    logout(request)
    return redirect('login')

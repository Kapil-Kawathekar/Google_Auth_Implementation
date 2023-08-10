from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from google.auth.transport import requests
import requests
from django.conf import settings
from google_auth_oauthlib.flow import InstalledAppFlow

# Scopes
SCOPES = ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"]  # Example scope


flow = InstalledAppFlow.from_client_secrets_file(
        settings.GOOGLE_CLIENT_SECRET_JSON_PATH,  # Replace with your client secret JSON file
        SCOPES,
        )
flow.redirect_uri = settings.GOOGLE_REDIRECT_URI

class FetchTokenView(APIView):

    def get(self,request):
        # This will return the Authorization url user can copy paste that url in google and login 
        # after successful login it will redirected to redirect url
        authorization_url, _ = flow.authorization_url(prompt='consent',access_type='offline')
        return Response({'msg':'copy paste the authorization url on google','authorization_url': authorization_url})
        

class TokensProviderView(APIView):

   def get(self,request):
        # After Successful login it will redirected to this url
        # with the authorization code and using this auth code we will fetch access, id, refresh token

        code=request.GET.get('code')
        flow.fetch_token(code=code)

        print("Access token  : ",flow.credentials.token)
        print("REFRESH TOKEN  : ",flow.credentials.refresh_token)
        print("ID TOKEN  : ",flow.credentials.id_token)

        return JsonResponse({"access-token ":flow.credentials.token,"refresh token  ":flow.credentials.refresh_token,'id-token  ':flow.credentials.id_token})


class RefreshTokenView(APIView):

    def post(self,request):
        """This will take refresh token and  returns new access token and new id token"""

        refresh_token=request.data['refresh_token']
        token_endpoint = 'https://oauth2.googleapis.com/token'
        client_id = settings.GOOGLE_CLIENT_ID
        client_secret = settings.GOOGLE_CLIENT_SECRET

        payload = {
            'refresh_token': refresh_token,
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'refresh_token'
        }

        response = requests.post(token_endpoint, data=payload)

        if response.status_code == 200:
            token_data = response.json()
            new_access_token = token_data.get('access_token')
            new_id_token = token_data.get('id_token')
            return JsonResponse({"new access token ":new_access_token,"new id token":new_id_token})

        return JsonResponse({"msg":"Something went Wrong"})




class UserInfoView(APIView):

    def get(self,request):
        """Fetching user info using access token"""

        access_token=request.headers.get('Authorization').split(' ')[1]

        # If you pass only access token you will get only aud if you pass id token you will get only aud if you pass iss aud and other details
        # We can verify the id token using public key for authenticity  and to access the resource we have to use access token
        # tokeninfo_url = f'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={flow.credentials.id_token}'

        response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )

        return Response({"msg":response.json()})


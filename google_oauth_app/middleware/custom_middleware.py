from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import JsonResponse
import requests
import jwt
import base64

def verify_jwt_signature(jwt_token, rsa_public_key):
    """Verify the signature of of token"""
   
    try:
        decoded_token = jwt.decode(
            jwt_token,
            rsa_public_key,
            algorithms=['RS256'],
            audience="832968535023-7ujbh9gt0srer1u1gp8qmkk8e4tqobte.apps.googleusercontent.com",
            issuer='https://accounts.google.com'
        )
        return decoded_token
    except jwt.ExpiredSignatureError:
        print('Token expired')
        return None
    except jwt.InvalidTokenError:
        print('Invalid token')
        return None


class CustomAuthMiddleware():

    def __init__(self,get_response):
        self.get_response=get_response

    def __call__(self,request):

        excluded_urls = ['/api/validatetoken/','/api/refreshtoken/','/api/fetchtoken/']

        if request.path not in excluded_urls:
            print(request.headers['Authorization'].split(' ')[2])
            id_token = request.headers['Authorization'].split(' ')[2]

            jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
            # this google url doesnt provide jwks uri and x5c string only provide n and e so we form key from that
            jwks_response = requests.get(jwks_url)
            jwks_data = jwks_response.json()

            decoded_token = jwt.get_unverified_header(id_token)
            kid = decoded_token['kid']
            public_key = None
            for key in jwks_data['keys']:
                if key['kid'] == kid:
                    public_key = key
                    break

            if public_key:
                # Create an RSA public key from the provided modulus (n) and exponent (e)
                modulus = int.from_bytes(base64.urlsafe_b64decode(public_key['n'] + "=="), byteorder='big')
                exponent = int.from_bytes(base64.urlsafe_b64decode(public_key['e']), byteorder='big')
                rsa_public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())


            decoded_token = verify_jwt_signature(id_token, rsa_public_key)

            if decoded_token:
                print('Token signature verified:')
                print("Decoded Token  : ",decoded_token)
                return self.get_response(request)
            else:
                return JsonResponse({"msg":"Unauthorized"})

        response = self.get_response(request)
        return response

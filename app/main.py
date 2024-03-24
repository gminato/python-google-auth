from flask import Flask, render_template, url_for, redirect, session, request, jsonify
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
from functools import wraps
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
import os
import requests

app = Flask(__name__)
app.secret_key = os.urandom(12)

oauth = OAuth(app)

# Define Google Client ID
GOOGLE_CLIENT_ID = 'your-client-id.apps.googleusercontent.com'

@app.route("/")
def index():
    return render_template('index.html')

@app.route('/google/')
def google():
    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret='CLIENT_SECRET',  # Replace with your client secret
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    # Redirect to Google for authentication
    redirect_uri = url_for('google_auth', _external=True)
    session['nonce'] = generate_token()
    return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])

@app.route('/google/auth/')
def google_auth():
    # Exchange the authorization code for an access token
    token = oauth.google.authorize_access_token()
#     user = oauth.google.parse_id_token(token, nonce=session['nonce'])
#     session['user'] = user

    # Pass the access token to the frontend
    is_valid_token = validate_google_token(token)
    if not is_valid_token:
        return "Invalid token", 401

    # If the token is valid, make a request to the protected endpoint
    headers = {
        'Authorization': 'Bearer ' + token['id_token']
    }
    resource_response = requests.get('http://localhost:5000/api/resource', headers=headers)

    if resource_response.status_code == 200:
        return resource_response.json(), 200
    else:
        return "Error accessing resource", resource_response.status_code

def validate_google_token(token):
    try:
        # Verify the token with Google
      #   print( GOOGLE_CLIENT_ID)
        print(token)
        try:
            id_info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
            # print(json( id_info))
        except Exception as e:
            app.logger.error("Error verifying token: %s", e) 



        return True  # Token is valid
    except ValueError:
        # Token is invalid
        return False

# Decorator to check token in request headers
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = extract_token_from_header(request.headers)

        # Check if token is missing
        if not token:
            return "Token is missing", 401

        # Validate the token against Google
        is_valid = validate_google_token(token)

        if not is_valid:
            return "Token is invalid or expired", 401

        # If the token is valid, proceed with the function
        return f(*args, **kwargs)

    return decorated_function

def extract_token_from_header(headers):
    auth_header = headers.get('Authorization')
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    print(parts[1])  
    return parts[1]

# Example of using the token_required decorator
@app.route('/protected')
@token_required
def protected():
    return "Access Granted"

@app.route('/api/resource')
@token_required
def get_resource():
    return {'data': 'This is a protected resource'}

if __name__ == '__main__':
    app.run()

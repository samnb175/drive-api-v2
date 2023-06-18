# Python standard libraries
import json
import os
import sqlite3
import google.oauth2.credentials
import googleapiclient.discovery
from googleapiclient.discovery import build
from flask import Flask, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_cors import CORS
from oauthlib.oauth2 import WebApplicationClient
import requests

# Internal imports
from db import init_db_command
from user import User

# Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", None)
ACCESS_TOKEN_URI = os.getenv("ACCESS_TOKEN_URI", None)
SERVER_BASE_URL = os.getenv("SERVER_BASE_URL", None)
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL", None)
SCOPE = os.getenv("SCOPE", None)


# Flask app setup
app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)

# Database setup
try:
    init_db_command()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route("/")
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">Google Login</a>'

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


urlToRedirect = {}
creds = {}

@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri = SERVER_BASE_URL + "/login/callback",
        scope = SCOPE,
    )

    # Url to redirect user once logged in
    urlToRedirect['url'] = request.args.get('url')

    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response = request.url,
        redirect_url = request.base_url,
        code = code
    )
    token_response = requests.post(
        token_url,
        headers = headers,
        data = body,
        auth = (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    tokenResponse = client.parse_request_body_response(json.dumps(token_response.json()))
    creds['creds'] = build_credentials(tokenResponse["access_token"])

    # Now that you have tokens - find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400


    # Create a user in your db with the information provided
    # by Google
    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )

    # Doesn't exist? Add it to the database.
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    # Begin user session by logging the user in
    login_user(user)

    # Send user back to homepage
    my_url = urlToRedirect['url']
    urlToRedirect.clear()
    return redirect(my_url + '?key=' + userinfo_response.json()["sub"])


@app.route("/getdata")
def getData():
    if request.args.get('key'):
        uniKey = request.args.get('key')

        if User.get(uniKey):
            userFromId = User.get(uniKey)
            logout_user()
            login_user(userFromId)
            fileData = getFiles(creds['creds'])
            return fileData
        return 'User Not Found'
    return 'Not Logged In'

@app.route("/logout")
@login_required
def logout():
    creds.clear()
    logout_user()
    homeUrl = request.args.get('url')
    return redirect(homeUrl)


################################################
def build_credentials(token):

    return google.oauth2.credentials.Credentials(
                token,
                client_id=GOOGLE_CLIENT_ID,
                client_secret=GOOGLE_CLIENT_SECRET,
                token_uri=ACCESS_TOKEN_URI)

def getService(service,ps,f,q):
    results = service.files().list(
            pageSize=ps,
            fields=f,
            q=q
        ).execute()
    listOfOutput = results.get('files', {})
    return listOfOutput

# Functions for Permission
def get_permission(service, file_id):
    permission = service.permissions().list(fileId=file_id).execute()
    return permission.get('permissions', [])[0]['type']

def set_permission(service, file_id):
    permission = {'type': 'anyone',
                    'role': 'reader'}
    return service.permissions().create(fileId=file_id,body=permission).execute()

def delete_permission(service, file_id):
    permissionsObj = get_permission(service, file_id)
    return service.permissions().delete(fileId=file_id, permissionId=permissionsObj[1]['id'])


# Function to get all folders & mp4
def getFiles(creds):
    service = build('drive', 'v3', credentials=creds)

    pageSize = 100
    fields0 = "files(id, name, parents)"
    query0 = "mimeType contains 'folder'"

    folders = getService(service,pageSize,fields0,query0)
    result = []

    for folder in folders:
        folderObj = {}
        fields = "files(id,name,webContentLink)"
        query = "'{}' in parents".format(folder['id']) + " and mimeType = 'video/mp4'"
        allFiles = getService(service,pageSize,fields,query)
        for file in allFiles:
            if file["id"]:
                request = service.files().get_media(fileId=file["id"], acknowledgeAbuse=True)
                downloadUrl = request.uri + "&key=AIzaSyDl-1LKLHvxr3ZgNdYTosvkESOEJwh_oEo"
                file["webContentLink"] = downloadUrl

        folderObj['folderId'] = folder['id']
        folderObj['folderName'] = folder['name']
        folderObj['folderParent'] = folder['parents']
        folderObj['folderContent'] = allFiles

        childPermissions = get_permission(service, folder['id'])
        if not(childPermissions == 'anyone'):
            set_permission(service, folder['id'])

        result.append(folderObj)

    return result


###############################################
if __name__ == "__main__":
    CORS(app)
    app.run()
    # app.run(ssl_context="adhoc")

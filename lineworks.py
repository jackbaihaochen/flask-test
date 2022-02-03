from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import time
from datetime import datetime
import environ
from pathlib import Path
import os
import requests
import json
from line_bot.models import LineAuthInfo

# Settings
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
# Initialise environment variables
env = environ.Env()
environ.Env.read_env('../.env')
# API
API_ID = 'piM8dniNdZRC0EZhpdRz'

# class for Line Auth
class LineAuth():
    # Get Access Token: Retrieve from DB, otherwise from Post request
    def get_access_token(self):
        result = self.get_access_token_from_db()
        # if access_token exists and valid
        if(result['access_token']):
            print('Access Token retrieved from DB.')
            return result['access_token']
        # if access_token is invalid but refresh_token exists and valid
        elif(result['refresh_token']):
            print('Access Token retrieved through refresh token.')
            return self.get_access_token_through_refresh_token(result['refresh_token'])
        # if no valid data in DB
        else:
            print('Access Token retrieved by post.')
            return self.get_access_token_by_post()
            
    # Generate JWT for Line Service Account Auth
    def gen_line_service_auth_jwt(payload = None, key = 'secret', algorithm = 'RS256', headers={"alg":"RS256","typ":"JWT"}):
        payload = {
            "iss": env('LINE_CLIENT_ID'),
            "sub": env('LINE_SERVICE_ACCOUNT'),
            "iat": int(time.time()),
            "exp": int(time.time() + 60*60),
        }
        key_file = open(os.path.join(BASE_DIR, 'private_20220126175641.key') ,'r')
        key_content = key_file.read()
        key_file.close()
        key = serialization.load_pem_private_key(bytes(key_content, encoding='utf8'), password=None, backend=default_backend())
        encoded = jwt.encode(payload, key, algorithm, headers)
        print('JWT generated: ' + encoded)
        return encoded

    # Get Access Token by Post request.
    def get_access_token_by_post(self):
        url = 'https://auth.worksmobile.com/oauth2/v2.0/token'
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        data = {
            'assertion': self.gen_line_service_auth_jwt(),
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'client_id': env('LINE_CLIENT_ID'),
            'client_secret': env('LINE_CLIENT_SECRET'),
            'scope': 'bot,bot.read,user.read',
        }
        response = requests.post(url=url, data=data, headers=headers)
        access_token = self.update_access_token_info_to_db(response)
        return access_token

    # Get Access Token from DB.
    def get_access_token_from_db(self):
        db_access_token = False
        db_refresh_token = False
        line_auth_info_set = LineAuthInfo.objects.all()
        # check if token is stored in DB
        if(line_auth_info_set.exists()):
            try:
                db_access_token = line_auth_info_set.get(key = 'access_token')
                db_refresh_token = line_auth_info_set.get(key = 'refresh_token')
                db_access_token_expires_time = line_auth_info_set.get(key = 'access_token_expires_time')
                db_refresh_token_expires_time = line_auth_info_set.get(key = 'refresh_token_expires_time')
                db_access_token = db_access_token.value
                db_refresh_token = db_refresh_token.value
                db_access_token_expires_time = db_access_token_expires_time.value
                db_refresh_token_expires_time = db_refresh_token_expires_time.value
                # check if token is expired
                db_access_token_expires_time = datetime.strptime(db_access_token_expires_time, '%Y-%m-%d %H:%M:%S')
                if(db_access_token_expires_time<=datetime.now()):
                    db_access_token = False
                db_refresh_token_expires_time = datetime.strptime(db_refresh_token_expires_time, '%Y-%m-%d %H:%M:%S')
                if(db_refresh_token_expires_time<=datetime.now()):
                    db_refresh_token = False
            except ObjectDoesNotExist:
                # if no data in DB, return a false signal
                print("No data in DB.")
                db_access_token = False
                db_refresh_token = False

        return {'access_token': db_access_token, 'refresh_token': db_refresh_token}
    
    # Get Access Token through Refresh Token
    def get_access_token_through_refresh_token(self, refresh_token):
        url = 'https://auth.worksmobile.com/oauth2/v2.0/token'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
            'client_id': env('LINE_CLIENT_ID'),
            'client_secret': env('LINE_CLIENT_SECRET'),
        }
        response = requests.post(url=url,data=data,headers=headers)
        access_token = self.update_access_token_info_to_db(response)
        return access_token

    # Insert Access Token Info into DB
    def update_access_token_info_to_db(self, response):
        # get data from response
        response = response.json()
        access_token = response.get('access_token')
        refresh_token = response.get('refresh_token')
        expires_in = response.get('expires_in')
        access_token_expires_time = datetime.fromtimestamp(int(datetime.now().timestamp() + int(expires_in)))
        print('Access token response: \n' + json.dumps(response))

        # update/insert data into DB
        line_auth_info_set = LineAuthInfo.objects.all()
        # if data exists, update; if doesn't, create.
        db_access_token = line_auth_info_set.update_or_create(
            key = 'access_token',
            defaults = {
                'value': access_token,
            }
        )
        db_access_token_expires_time = line_auth_info_set.update_or_create(
            key = 'access_token_expires_time',
            defaults = {
                'value': access_token_expires_time,
            }
        )
        # If there is a refresh token, then save it. If the access token is retrieved through refresh token, then the response will not contain refresh token.
        if(refresh_token):
            db_refresh_token = line_auth_info_set.update_or_create(
                key = 'refresh_token',
                defaults = {
                    'value': refresh_token,
                }
            )
            refresh_token_expires_time = datetime.fromtimestamp(int(datetime.now().timestamp() + int(60*60*24*90)))
            db_refresh_token_expires_time = line_auth_info_set.update_or_create(
                key = 'refresh_token_expires_time',
                defaults = {
                    'value': refresh_token_expires_time,
                }
            )
        print('Access Token saved to DB.')
        return access_token

# class for Line Bot
class LineBot():
    # constructor: require access_token, bot_id
    def __init__(self, access_token, bot_id):
        self.access_token = str(access_token)
        self.bot_id = str(bot_id)

    # Get Member List for a certain Domain
    def get_domain_member_list(self, domain_id, cursor=None, count=None):
        url = 'https://www.worksapis.com/v1.0/bots/' + self.bot_id + '/domains/' + str(domain_id) + '/members'
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
        }
        params = {}
        # if either cursor or count exists, prepare the url with query string
        if(cursor):
            params['cursor'] = cursor
        if(count):
            params['count'] = count
        response = requests.get(url=url, params=params, headers=headers).json()
        print('Domain Member List Response: \n' + json.dumps(response))
        members = response.get('members')
        next_cursor = None
        response_metadata = response.get('responseMetaData')
        if(response_metadata):
            next_cursor = response_metadata.get('nextCursor')
        return {'member_list': members, 'next_cursor': next_cursor}

    # Send Message to one user
    def send_message_to_one(self, user_id, message):
        url = 'https://www.worksapis.com/v1.0/bots/' + self.bot_id + '/users/' + user_id + '/messages'
        print('Send Message url is: ' + url)
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json',
        }
        data = {
            'content': {
                'type': "text",
                'text': message,
            },
        }
        data = json.dumps(data)
        response = requests.post(url=url, data=data, headers=headers).status_code
        print('Message sent. Response: \n' + 'Succeeded' if response == 201 else 'Failed')
        return response == 201

    # Register one user to the bot
    def register_one_user(self, domain_id, user_id):
        url = 'https://www.worksapis.com/v1.0/bots/' + self.bot_id + '/domains/' + str(domain_id) + '/members'
        print('Register url is: ' + url)
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
        }
        data = {
            'userId': user_id
        }
        response = requests.post(url=url, data=data, headers=headers).json()
        print('Register signal sent. Response: \n' + json.dumps(response))
        return response

# class for old line bot
class OldLineBot():
    # register the bot
    def register_bot(self):
        url = 'https://apis.worksmobile.com/r/' + 'jp2nSdmaqsgFW' + '/message/v1/bot'
        print('Register url is: ' + url)
        headers = {
            "consumerKey": "piM8dniNdZRC0EZhpdRz"
        }
        data = {
            "name": "echo bot",
            "photoUrl": "https://developers.worksmobile.com/favicon.png",
            "description": "WorksMobile's A.I. conversation enabled bot",
            "managers": ["bai.jack@jackbai"],
            'useCallback': True,
            'callbackUrl': 'https://djangotestbai.herokuapp.com/line/callback',
            'callbackEvents': ['text'],
        }
        response = requests.post(url=url, data=data).json()
        print('Bot Register signal sent. Response: \n' + json.dumps(response))
        return json.dumps(response)
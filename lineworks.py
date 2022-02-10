from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import time
from datetime import datetime
import os
import requests
import json
from mongo import mongo_collection_connection, mongo_connection, mongo_insert_document
from logging import getLogger


# class for Line Auth V2 referring API 2.0
class LineAuthV2():
    # Initialization with necessary information
    def __init__(self, client_secret, client_id, service_account, redirect_url, scope = 'bot,bot.read', auth_type = 'OAuth') -> None:
        self.logger = getLogger(__name__)
        self.client_secret = client_secret
        self.client_id = client_id
        self.service_account = service_account
        self.scope = scope
        self.auth_type = auth_type
        self.redirect_url = redirect_url
        self.user_auth_url = 'https://auth.worksmobile.com/oauth2/v2.0/authorize?client_id={client_id}&redirect_uri={redirect_url}&scope={scope}&response_type=code&state=aBcDeF'.format(client_id = self.client_id, redirect_url = self.redirect_url, scope = self.scope)


    # Get Access Token: Retrieve from DB, otherwise from Post request
    def get_access_token(self, authorization_code = None):

        self.logger.debug('Start')

        # if access_token exists and valid in DB
        result = self.get_access_token_from_db()
        if(result['access_token']):
            self.logger.info('Access Token retrieved from DB.')
            self.logger.debug('End')
            return result['access_token']
        # if access_token is invalid but refresh_token exists and valid in DB
        elif(result['refresh_token']):
            self.logger.info('Access Token retrieved through refresh token.')
            self.logger.debug('End')
            return self.get_access_token_through_refresh_token(result['refresh_token'])
        # if no valid data in DB
        else:
            # if the specified auth type is User Account Auth (OAuth)
            if(self.auth_type == 'OAuth'):
                self.logger.info('Access Token retrieved by OAuth.')
                self.logger.debug('End')
                return self.get_access_token_by_oauth(authorization_code)
            # if the specified auth type is Service Account Auth (JWT)
            else:
                self.logger.info('Access Token retrieved by JWT.')
                self.logger.debug('End')
                return self.get_access_token_by_jwt()


    # Generate JWT for Line Service Account Auth
    def gen_line_service_auth_jwt(self, payload = None, key = 'secret', algorithm = 'RS256', headers={"alg":"RS256","typ":"JWT"}):

        self.logger.debug('Start')

        payload = {
            "iss": self.client_id,
            "sub": self.service_account,
            "iat": int(time.time()),
            "exp": int(time.time() + 60*60),
        }
        key_file = open(os.path.join(BASE_DIR, 'private_20220126175641.key') ,'r')
        key_content = key_file.read()
        key_file.close()
        key = serialization.load_pem_private_key(bytes(key_content, encoding='utf8'), password=None, backend=default_backend())
        encoded = jwt.encode(payload, key, algorithm, headers)
        self.logger.info('JWT generated: ' + encoded)
        self.logger.debug('End')
        return encoded


    # Get Access Token by Service Account Auth (JWT) request.
    def get_access_token_by_jwt(self):

        self.logger.debug('Start')

        url = 'https://auth.worksmobile.com/oauth2/v2.0/token'
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        data = {
            'assertion': self.gen_line_service_auth_jwt(),
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope,
        }
        response = requests.post(url=url, data=data, headers=headers)
        response = response.json()
        access_token = response.get('access_token')

        self.update_access_token_info_to_db(response)
        self.logger.debug('End')
        return access_token

    
    # # Get Access Token by User Account Auth (OAuth) request.
    def get_access_token_by_oauth(self, authorization_code):

        self.logger.debug('Start')

        if(authorization_code):
            url = 'https://auth.worksmobile.com/oauth2/v2.0/token'
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = {
                'code': authorization_code,
                'grant_type': 'authorization_code',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            }
            response = requests.post(url=url, data=data, headers=headers)
            response = response.json()
            access_token = response.get('access_token')

            self.update_access_token_info_to_db(response)
            self.logger.debug('End')
            return access_token
        else:
            self.logger.debug('End')
            return False
        


    # Get Access Token from DB.
    def get_access_token_from_db(self):

        self.logger.debug('Start')

        db_access_token = False
        db_refresh_token = False

        # Using Non-relational DB
        collection = mongo_collection_connection()
        document = collection.find_one({ 'access_token': { '$exists': 'true' }})
        if(document):
            db_access_token = document['access_token']
            db_refresh_token = document['refresh_token']
            db_access_token_expiration_time = document['access_token_expiration_time']
            db_refresh_token_expiration_time = document['refresh_token_expiration_time']
            # check if access token is expired
            if(db_access_token_expiration_time <= datetime.now()):
                self.logger.info("Access_token in DB expired")
                db_access_token = False
                # only if access token is expired, would we check whether refresh token is expired. If access token is not expired, then we can just use access token.
                if(db_refresh_token_expiration_time <= datetime.now()):
                    self.logger.info("Refresh_token in DB expired")
                    db_refresh_token = False
        else:
            self.logger.info("No data in DB")
            db_access_token = False
            db_refresh_token = False

        # Using Relational DB
        # line_auth_info_set = LineAuthInfo.objects.all()
        # # check if token is stored in DB
        # if(line_auth_info_set.exists()):
        #     try:
        #         db_access_token = line_auth_info_set.get(key = 'access_token')
        #         db_refresh_token = line_auth_info_set.get(key = 'refresh_token')
        #         db_access_token_expiration_time = line_auth_info_set.get(key = 'access_token_expiration_time')
        #         db_refresh_token_expiration_time = line_auth_info_set.get(key = 'refresh_token_expiration_time')
        #         db_access_token = db_access_token.value
        #         db_refresh_token = db_refresh_token.value
        #         db_access_token_expiration_time = db_access_token_expiration_time.value
        #         db_refresh_token_expiration_time = db_refresh_token_expiration_time.value
        #         # check if token is expired
        #         db_access_token_expiration_time = datetime.strptime(db_access_token_expiration_time, '%Y-%m-%d %H:%M:%S')
        #         if(db_access_token_expiration_time<=datetime.now()):
        #             db_access_token = False
        #         db_refresh_token_expiration_time = datetime.strptime(db_refresh_token_expiration_time, '%Y-%m-%d %H:%M:%S')
        #         if(db_refresh_token_expiration_time<=datetime.now()):
        #             db_refresh_token = False
        #     except ObjectDoesNotExist:
        #         # if no data in DB, return a false signal
        #         print("No data in DB.")
        #         db_access_token = False
        #         db_refresh_token = False

        self.logger.debug('End')
        return {'access_token': db_access_token, 'refresh_token': db_refresh_token}
    

    # Get Access Token through Refresh Token
    def get_access_token_through_refresh_token(self, refresh_token):

        self.logger.debug('Start')

        # Get access token
        url = 'https://auth.worksmobile.com/oauth2/v2.0/token'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        response = requests.post(url=url,data=data,headers=headers)
        response = response.json()
        access_token = response.get('access_token')

        # Update DB
        self.update_access_token_info_to_db(response)
        self.logger.debug('End')
        return access_token


    # Insert Access Token Info into DB
    def update_access_token_info_to_db(self, response):

        self.logger.debug('Start')

        # Get data from response
        access_token = response.get('access_token')
        refresh_token = response.get('refresh_token')
        expires_in = response.get('expires_in')
        access_token_expiration_time = datetime.fromtimestamp(int(datetime.now().timestamp() + int(expires_in)))
        print('Access token response: \n' + json.dumps(response))

        # Using Non-relational DB
        collection = mongo_collection_connection()
        myquery = { 'access_token': { '$exists': 'true' } }
        newvalues = { 'access_token': access_token, 'access_token_expiration_time': access_token_expiration_time}
        # If there is a refresh token, then save it. If the access token is retrieved through refresh token, then the response will not contain refresh token.
        if(refresh_token):
            newvalues['refresh_token'] = refresh_token
            newvalues['refresh_token_expiration_time'] = datetime.fromtimestamp(int(datetime.now().timestamp() + int(60*60*24*90)))
        update_result = collection.find_one_and_update(myquery, {'$set': newvalues})
        # If the document itself doesn't exist, update result will be None. Then create the document.
        if(not update_result):
            collection.insert_one(newvalues)

        # Using Relational DB
        # # update/insert data into DB
        # line_auth_info_set = LineAuthInfo.objects.all()
        # # if data exists, update; if doesn't, create.
        # db_access_token = line_auth_info_set.update_or_create(
        #     key = 'access_token',
        #     defaults = {
        #         'value': access_token,
        #     }
        # )
        # db_access_token_expiration_time = line_auth_info_set.update_or_create(
        #     key = 'access_token_expiration_time',
        #     defaults = {
        #         'value': access_token_expiration_time,
        #     }
        # )
        # # If there is a refresh token, then save it. If the access token is retrieved through refresh token, then the response will not contain refresh token.
        # if(refresh_token):
        #     db_refresh_token = line_auth_info_set.update_or_create(
        #         key = 'refresh_token',
        #         defaults = {
        #             'value': refresh_token,
        #         }
        #     )
        #     refresh_token_expiration_time = datetime.fromtimestamp(int(datetime.now().timestamp() + int(60*60*24*90)))
        #     db_refresh_token_expiration_time = line_auth_info_set.update_or_create(
        #         key = 'refresh_token_expiration_time',
        #         defaults = {
        #             'value': refresh_token_expiration_time,
        #         }
        #     )
        # print('Access Token saved to DB.')
        self.logger.debug('End')
        return access_token

# class for Line Bot
class LineBot():
    # constructor: require access_token, bot_id
    def __init__(self, access_token, bot_id):
        self.logger = getLogger(__name__)
        self.access_token = str(access_token)
        self.bot_id = str(bot_id)

    # Get Member List for a certain Domain
    def get_domain_member_list(self, domain_id, cursor=None, count=None):

        self.logger.debug('Start')

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
        self.logger.info('Domain Member List Response: ' + json.dumps(response))
        members = response.get('members')
        next_cursor = None
        response_metadata = response.get('responseMetaData')
        if(response_metadata):
            next_cursor = response_metadata.get('nextCursor')
        self.logger.debug('End')
        return {'member_list': members, 'next_cursor': next_cursor}

    # Send Message to one user
    def send_message_to_one(self, user_id, data: dict):

        self.logger.debug('Start')

        url = 'https://www.worksapis.com/v1.0/bots/' + self.bot_id + '/users/' + user_id + '/messages'
        self.logger.info('Send Message url is: ' + url)
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json',
        }
        data = json.dumps(data)
        response = requests.post(url=url, data=data, headers=headers)
        self.logger.info('Message sent. Response: ' + str(response))
        self.logger.debug('End')
        return str(response)

    # Send Text Message to one user
    def send_text_message_to_one(self, user_id, text_msg):
        self.logger.debug('Start')
        data = {
            "content": {
                "type": "text",
                "text": text_msg
            }
        }
        response = self.send_message_to_one(user_id, data)
        self.logger.debug('End')
        return response

    # Send Image Message to one user
    def send_image_message_to_one(self, user_id, image_url = None, resource_id = None, source = 'url'):
        self.logger.debug('Start')
        if(source == 'url'):
            data = {
                "content": {
                    "type": "image",
                    "originalContentUrl": image_url
                }
            }
        elif(source == 'id'):
            data = {
                "content": {
                    "type": "image",
                    "fileId": resource_id
                }
            }
        else:
            self.logger.warning('Image resource unknown.')
            self.logger.debug('End')
            return False
        response = self.send_message_to_one(user_id, data)
        self.logger.debug('End')
        return response
    
    # Send Link Message to one user
    def send_link_message_to_one(self, user_id, content_text, link_text, link):
        self.logger.debug('Start')
        data = {
            "content": {
                "type": "link",
                "contentText": content_text,
                "linkText": link_text,
                "link": link
            }
        }
        response = self.send_message_to_one(user_id, data)
        self.logger.debug('End')
        return response
    
    # Send Link Message to one user
    def send_link_message_to_one(self, user_id, content_text, link_text, link):
        self.logger.debug('Start')
        data = {
            "content": {
                "type": "link",
                "contentText": content_text,
                "linkText": link_text,
                "link": link
            }
        }
        response = self.send_message_to_one(user_id, data)
        self.logger.debug('End')
        return response

    # Send Stamp Message to one user
    def send_stamp_message_to_one(self, user_id, package_id, sticker_id):
        self.logger.debug('Start')
        data = {
            "content": {
                "type": "stamp",
                "packageId": package_id,
                "stickerId": sticker_id,
            }
        }
        response = self.send_message_to_one(user_id, data)
        self.logger.debug('End')
        return response
    
    # Send Button Template Message to one user
    def send_button_template_message_to_one(self, user_id, content_text):
        self.logger.debug('Start')
        data = {
            "content": {
                "type": "button_template",
                "contentText": content_text,
                "actions": [
                    {
                        "type": "postback",
                        "label": "label1",
                        "data": "choice1",
                        "displayText": "displayText1",
                    },
                    {
                        "type": "postback",
                        "label": "label2",
                        "data": "choice2",
                        "displayText": "displayText2",
                    },
                ]
            }
        }
        response = self.send_message_to_one(user_id, data)
        self.logger.debug('End')
        return response
    
    # Register the bot to one user
    def register_one_user(self, domain_id, user_id):
        self.logger.debug('Start')
        url = 'https://www.worksapis.com/v1.0/bots/' + self.bot_id + '/domains/' + str(domain_id) + '/members'
        self.logger.info('Register url is: ' + url)
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
        }
        data = {
            'userId': user_id
        }
        response = requests.post(url=url, data=data, headers=headers).json()
        self.logger.info('Register signal sent. Response: ' + json.dumps(response))
        self.logger.debug('End')
        return response


    # register the bot
    def register_bot(self, bot_name, photo_url = 'https://developers.worksmobile.com/favicon.png', description = "WorksMobile's A.I. conversation enabled bot", administrators = ['bai.jack@jackbai'], enable_callback = True, callback_url = 'https://flask-test-bai.herokuapp.com/line_works/callback_url', callback_events = ['text', 'file', 'image', 'sticker', 'location']):
        self.logger.debug('Start')
        url = 'https://www.worksapis.com/v1.0/bots'
        self.logger.info('Register url is: ' + url)
        headers = {
            'Authorization': 'Bearer {token}'.format(token = self.access_token),
            'Content-Type': 'application/json',
        }
        if(enable_callback):
            data = {
                "botName": bot_name,
                "photoUrl": photo_url,
                "description": description,
                "administrators": administrators,
                'enableCallback': enable_callback,
                'callbackUrl': callback_url,
                'callbackEvents': callback_events,
            }
        else:
            data = {
                "botName": bot_name,
                "photoUrl": photo_url,
                "description": description,
                "administrators": administrators,
            }
        data = json.dumps(data)
        response = requests.post(url=url, data=data, headers = headers).json()
        self.logger.info('Bot Register signal sent. Response: ' + json.dumps(response))
        mongo_insert_document(json.dumps(response))
        self.logger.debug('End')
        return json.dumps(response)
    
    # callback handler
    def callback_handler(self, response):
        self.logger.debug('Start')
        user_id = response['source']['userId']
        # channel_id = response['source']['channelId']
        issued_time = response['issuedTime']
        self.logger.info('Received callback data :' + json.dumps(response))

        type = response['type']
        if(type == 'message'):
            content_type = response['content']['type']
            self.logger.debug('Callback type is message. Auto Repeat.')
            if(content_type == 'text'):
                self.send_text_message_to_one(user_id, response['content']['text'])
            elif(content_type == 'location'):
                self.send_text_message_to_one(user_id, response['content']['address'])
            elif(content_type == 'sticker'):
                self.send_stamp_message_to_one(user_id, response['content']['packageId'], response['content']['stickerId'])
            elif(content_type == 'image'):
                self.send_image_message_to_one(user_id, source='id', resource_id=response['content']['resourceId'])
            else:
                self.logger.warning('Unaccepted content type.')
        elif(type == 'postback'):
            data = response['data']
            self.logger.info('Callback type is postback. The postback data is: ' + data)
            self.send_text_message_to_one(user_id, data)
        
        self.logger.debug('End')
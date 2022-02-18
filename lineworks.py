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
    def __init__(self, client_secret, client_id, service_account, redirect_url = None, scope = 'bot,bot.read,user.read', auth_type = None) -> None:
        self.logger = getLogger(__name__)
        self.client_secret = client_secret
        self.client_id = client_id
        self.service_account = service_account
        self.scope = scope
        self.auth_type = auth_type
        self.redirect_url = redirect_url
        self.user_auth_url = 'https://auth.worksmobile.com/oauth2/v2.0/authorize?client_id={client_id}&redirect_uri={redirect_url}&scope={scope}&response_type=code&state=aBcDeF'.format(client_id = self.client_id, redirect_url = self.redirect_url, scope = self.scope)


    # Get Access Token: Retrieve from DB, otherwise from Post request
    def get_access_token(self, authorization_code = None, private_key = None):

        self.logger.debug('Start')

        if(self.auth_type):
            # if the specified auth type is User Account Auth (OAuth)
            if(self.auth_type == 'OAuth'):
                print('Access Token retrieved by OAuth.')
                self.logger.debug('End')
                return self.get_access_token_by_oauth(authorization_code)
            # if the specified auth type is Service Account Auth (JWT)
            else:
                print('Access Token retrieved by JWT.')
                self.logger.debug('End')
                return self.get_access_token_by_jwt(private_key)
        else:
            # if access_token exists and valid in DB
            result = self.get_access_token_from_db()
            if(result['access_token']):
                print('Access Token retrieved from DB.')
                self.logger.debug('End')
                return result['access_token']
            # if access_token is invalid but refresh_token exists and valid in DB
            elif(result['refresh_token']):
                print('Access Token retrieved through refresh token.')
                self.logger.debug('End')
                return self.get_access_token_through_refresh_token(result['refresh_token'])
            # if the specified auth type is Service Account Auth (JWT)
            else:
                print('Access Token retrieved by JWT.')
                self.logger.debug('End')
                return self.get_access_token_by_jwt()
  


    # Generate JWT for Line Service Account Auth
    def gen_line_service_auth_jwt(self, payload = None, private_key = 'secret', algorithm = 'RS256', headers={"alg":"RS256","typ":"JWT"}):

        self.logger.debug('Start')

        payload = {
            "iss": self.client_id,
            "sub": self.service_account,
            "iat": int(time.time()),
            "exp": int(time.time() + 60*60),
        }
        test_private_key = """-----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCiKs4L5Kaht6Pe
        lToeJ+AyOwrTwi+ELJ6HhLAcXXBegYLuU7dp48g50NXAX6N0PGnjzQ1jmqBskLYJ
        76AfmIh/mnJI5oTucpKAiLCOS0ouU7hpm3QvftavgBwl5avIf8qLAaFxCDOAA/Gc
        SeHcKflgrk8RGWO9Vq1AReVrRjF02YpvWjRNXtXy+GTJQl/h5woXW1ZDSFa2697b
        UCBlCj3GKZsyhF7yXGSAdGWOSE2PKX7XT2e9DD166lYLnsuYeK5AP4qqFSW2DzoS
        pjFidmTbXnTLpeUvAjTXK2HU2OsFShlHtEIZjz5yCg24Gow1Tm7IR2+W6yaxJacR
        ueOoRezbAgMBAAECggEBAIK7YUpDNXYPlmKdCLJA0UONR4g49pdmZRK5DESBq1H0
        tHmvMaCCyeqaCYfBUgMlpPPJXa7be9Kpwqc1728pR3kfKFzOwYF9Cc/m4faEibPZ
        OESi1sJnTWlELOz8P0UuiDkRwnVd+C6Of1vQT+1uRSUEwKb3Qenkk1zKPE4D02Dv
        qECMJlPxtJCjUdxcPlSrtxNdPcS7wO8/HbDS7fQSegt7+4zMa1I0qDG+5zTwcHcC
        HsUwhYVAguy6Pa9xn0YAoKQ6XYLFLhaQLp5rX4bcdIcbZgv4TLY+L7EuxHOCRTBj
        IwE+oDPM3Pj5DXTJMyUew7jmEzEbCD2jNfO4oBMH/rkCgYEA5EBEqmjQdByh/g9+
        PflqUhbgBPAMUxGm/TLQhGvuTOxggvYS8scd0Ot/F/4PcYyVdr1aetyCedSP4Gx/
        fD26d8E44y2zM3rGCgBm6jAy1OaAn6WaoKLbPBlGXXee3FCXHNBvFI1jDmHUSTkD
        b3ZTswnrwItcIkw/0dXfuDRPl/8CgYEAteHYeg/uu0rbVEBglEaf3nICXCKuMHiM
        074J0nhM3+CVZLt9twJBv5JigpaEoDhF07mwze9jqeAsYwkyknEOjCPtMVBwztO7
        egeHcRbKTshLJTaQuktVxjOuOfVbKIE1sz6OUqC1E+0yVvmyUAYgLgj1s3VfZjEL
        W6+UDBrDCyUCf0kcTOJIsHyAr2Kxk75GJcgli5wJR+lTvilcHW5NJAd/r2pDZ85b
        +TDyPcNxnYDBhx6BiHnSJ/jeHTfFiRBCtXembJJYEQ5sRQLvHgflaGLJcmmwodbS
        U2bssZ0+s6PeLIkOOoZaw1/X9id+G5uYSzcN9nW2LczOn6KW3xIhr10CgYEArXCb
        PPK6hbGBa1skfeDHDJmNdIzBrIkYScZ7mU+MhySjcXZ1EDI/vk36UGr2N87Rj3AQ
        kKCKWnDiAuK/bfQPmkWcJx19JU21Bk3ts0K3Ut8fAXKCGpRCTAn2R2CYOAzWx4GM
        uHB1nHXhPh1IE5Vz1FJI8oOnoEx+d0T8GXrfqV0CgYBViwlBgsLaHLXWjDcH2nNX
        GER+6M+sVnBZ1hC3aTKts4aw7q3IY0CHUi6zt+PZPbe4tt8AqnBzmMx7OFS2NstF
        JMkivLz6s4aIvutRyGTWBUPlMmf1X37DMVPwpD/H2x5lUTf7rXI7HFNRPb0ZjolV
        2t/2ZJJeH+EDBarkMpO2mQ==
        -----END PRIVATE KEY-----"""
        # begin = '-----BEGIN PRIVATE KEY-----'
        # end = '-----END PRIVATE KEY-----'
        # private_key = begin + private_key[len(begin):-(len(end))].replace(' ','\n') + end
        test_key = test_private_key.encode("utf-8")
        # key = private_key.encode("utf-8")
        encoded = jwt.encode(payload, test_key, algorithm, headers)
        print('JWT generated: ' + encoded)
        self.logger.debug('End')
        return encoded


    # Get Access Token by Service Account Auth (JWT) request.
    def get_access_token_by_jwt(self, private_key):

        self.logger.debug('Start')

        url = 'https://auth.worksmobile.com/oauth2/v2.0/token'
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        data = {
            'assertion': self.gen_line_service_auth_jwt(private_key = private_key),
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope,
        }
        response = requests.post(url=url, data=data, headers=headers)
        print(response.status_code)
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
                print("Access_token in DB expired")
                db_access_token = False
                # only if access token is expired, would we check whether refresh token is expired. If access token is not expired, then we can just use access token.
                if(db_refresh_token_expiration_time <= datetime.now()):
                    print("Refresh_token in DB expired")
                    db_refresh_token = False
        else:
            print("No data in DB")
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
        print('Domain Member List Response: ' + json.dumps(response))
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
        print('Send Message url is: ' + url)
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json',
        }
        data = json.dumps(data)
        response = requests.post(url=url, data=data, headers=headers)
        response = response.content
        print('Message sent. Response: ' + str(response))
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
    def send_image_message_to_one(self, user_id, image_url = None, file_id = None, source = 'url'):
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
                    "fileId": file_id
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
    
    # Send Quick Reply Message to one user
    def send_quick_reply_message_to_one(self, user_id, content_text):
        self.logger.debug('Start')
        data = {
            "content": {
                "type": "text",
                "text": content_text,
                "quickReply": {
                    "items": [
                        {
                        "imageUrl": "https://www.example.com/a.png",
                        "action": {
                            "type": "message",
                            "label": "Sushi",
                            "text": "Sushi"
                        }
                        },
                        {
                        "imageUrl": "https://www.example.com/b.png",
                        "action": {
                            "type": "message",
                            "label": "Italian",
                            "text": "Italian"
                        }
                        },
                        {
                        "action": {
                            "type": "camera",
                            "label": "Open Camera"
                        }
                        }
                    ]
                }
            }
        }
        response = self.send_message_to_one(user_id, data)
        self.logger.debug('End')
        return response
    
    # Register the bot to one user
    def register_one_user(self, domain_id, user_id):
        self.logger.debug('Start')
        url = 'https://www.worksapis.com/v1.0/bots/' + self.bot_id + '/domains/' + str(domain_id) + '/members'
        print('Register url is: ' + url)
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
        }
        data = {
            'userId': user_id
        }
        response = requests.post(url=url, data=data, headers=headers).json()
        print('Register signal sent. Response: ' + json.dumps(response))
        self.logger.debug('End')
        return response


    # register the bot
    def register_bot(self, bot_name, photo_url = 'https://developers.worksmobile.com/favicon.png', description = "WorksMobile's A.I. conversation enabled bot", administrators = ['bai.jack@jackbai'], enable_callback = True, callback_url = 'https://flask-test-bai.herokuapp.com/line_works/callback_url', callback_events = ['text', 'file', 'image', 'sticker', 'location']):
        self.logger.debug('Start')
        url = 'https://www.worksapis.com/v1.0/bots'
        print('Register url is: ' + url)
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
        print('Bot Register signal sent. Response: ' + json.dumps(response))
        mongo_insert_document(json.dumps(response))
        self.logger.debug('End')
        return json.dumps(response)
    

    # receiving image from user



    # callback handler
    def callback_handler(self, response):
        self.logger.debug('Start')
        user_id = response['source']['userId']
        # channel_id = response['source']['channelId']
        issued_time = response['issuedTime']
        print('Received callback data :' + json.dumps(response))

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
                self.send_image_message_to_one(user_id, source='id', file_id=response['content']['fileId'])
            else:
                self.logger.warning('Unaccepted content type.')
        elif(type == 'postback'):
            data = response['data']
            print('Callback type is postback. The postback data is: ' + data)
            self.send_text_message_to_one(user_id, data)
        
        self.logger.debug('End')
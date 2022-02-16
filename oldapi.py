import time
from urllib.parse import quote
import jwt
import requests

class LineBot():

    def __init__(self) -> None:
        self.api_id = 'jp2nSdmaqsgFW'
        self.bot_id = '1416961'
        self.account_id = 'bai.jack@jackbai'
        self.server_consumer_key = 'BfSMvJYpeZLLM8FeHQsP'
        self.private_key = open('./private_20220215181526.key', 'r').read()
        self.server_id = '7bbdf8e15b544b809a30dc08d0242c1d'
        self.server_token = 'Bearer '
        pass

    # Generate JWT for Line Service Account Auth
    def generate_jwt(self) -> str:
        print('Start'+__name__)
        payload = {
            "iss": self.server_id,
            "iat": int(time.time()),
            "exp": int(time.time() + 60*30),
        }
        algorithm = 'RS256'
        headers={"alg":"RS256","typ":"JWT"}
        encoded = jwt.encode(payload, self.private_key, algorithm, headers)
        print('JWT generated: %s' % encoded)
        print('End'+__name__)
        return encoded

    # Get server_token using JWT
    def get_server_token_by_jwt(self) -> str:
        print('Start'+__name__)
        url = 'https://auth.worksmobile.com/b/{api_id}/server/token'.format(api_id = self.api_id)
        headers = {
            'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        data = {
            'grant_type' : quote('urn:ietf:params:oauth:grant-type:jwt-bearer'),
            'assertion' : self.generate_jwt()
        }
        response = requests.post(url, data, headers = headers)
        print('')
        print('End'+__name__)


    # send message
    def send_message(self) -> bool:
        url = 'https://apis.worksmobile.com/r/{api_id}/message/v1/bot/{bot_id}/message/push'.format(api_id = self.api_id, bot_id = self.bot_id)
        data = {
            'accountId' : self.account_id,
            'content': {
                'type': 'text',
                'text': 'hello'
            }
        }
        headers = {
            'consumerKey': self.server_consumer_key,
            'Authorization': self.server_token
        }